package mcpcoverage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"gopkg.in/yaml.v3"
)

func LoadExclusions(path string) (map[string]Exclusion, error) {
	if path == "" {
		return map[string]Exclusion{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]Exclusion{}, nil
		}
		return nil, err
	}

	var exclusions []Exclusion
	if err := yaml.Unmarshal(data, &exclusions); err != nil {
		return nil, fmt.Errorf("parse exclusions: %w", err)
	}

	byID := make(map[string]Exclusion, len(exclusions))
	for _, exclusion := range exclusions {
		if exclusion.OperationID == "" || exclusion.Reason == "" {
			return nil, fmt.Errorf("exclusion entries require operationId and reason")
		}
		byID[exclusion.OperationID] = exclusion
	}
	return byID, nil
}

func BuildReport(source string, ops []Operation, mappings []Mapping, exclusions map[string]Exclusion) (Report, error) {
	for id, exclusion := range exclusions {
		if exclusion.OperationID == "" || exclusion.Reason == "" {
			return Report{}, fmt.Errorf("exclusion %q requires operationId and reason", id)
		}
	}

	mappingByID := make(map[string]Mapping, len(mappings))
	for _, mapping := range mappings {
		mappingByID[mapping.OperationID] = mapping
	}

	report := Report{Source: source}
	seen := make(map[string]bool, len(ops))
	for _, op := range ops {
		if seen[op.OperationID] {
			return Report{}, fmt.Errorf("duplicate operationId %q", op.OperationID)
		}
		seen[op.OperationID] = true

		record := Record{Operation: op, MappingType: ClassifyDefault(op), Status: StatusGap, Rationale: "No MCP mapping implemented yet."}
		if exclusion, ok := exclusions[op.OperationID]; ok {
			record.MappingType = MappingNone
			record.Status = StatusExcluded
			record.Rationale = exclusion.Reason
			record.ExclusionReason = exclusion.Reason
			record.ExclusionNotes = exclusion.Notes
			record.FollowUp = exclusion.FollowUp
		} else if mapping, ok := mappingByID[op.OperationID]; ok {
			if err := ValidateMapping(op, mapping); err != nil {
				return Report{}, fmt.Errorf("invalid mapping for %s: %w", op.OperationID, err)
			}
			record.MappingType = mapping.Type
			record.MCPName = mapping.Name
			record.ResourceURI = mapping.URI
			record.GrantPermission = mapping.GrantPermission
			record.Rationale = mapping.Rationale
			record.Destructive = mapping.Destructive || IsDestructive(op.Method, op.OperationID)
			record.Confirmation = mapping.Confirmation
			record.Status = StatusImplemented
		}
		report.Operations = append(report.Operations, record)
	}

	for _, mapping := range mappings {
		if !seen[mapping.OperationID] {
			return Report{}, fmt.Errorf("mapping references unknown operationId %q", mapping.OperationID)
		}
	}

	for _, record := range report.Operations {
		report.Summary.Total++
		switch record.Status {
		case StatusImplemented:
			report.Summary.Implemented++
		case StatusExcluded:
			report.Summary.Excluded++
		case StatusPlanned:
			report.Summary.Planned++
		default:
			report.Summary.Gaps++
		}
	}

	return report, nil
}

func WriteJSON(path string, report Report) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

func WriteMarkdown(path string, report Report) error {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# MCP Coverage\n\n")
	fmt.Fprintf(&b, "Source: `%s`\n\n", report.Source)
	fmt.Fprintf(&b, "| Total | Implemented | Gaps | Excluded | Planned |\n")
	fmt.Fprintf(&b, "|---:|---:|---:|---:|---:|\n")
	fmt.Fprintf(&b, "| %d | %d | %d | %d | %d |\n\n", report.Summary.Total, report.Summary.Implemented, report.Summary.Gaps, report.Summary.Excluded, report.Summary.Planned)

	byDomain := map[string][]Record{}
	for _, record := range report.Operations {
		byDomain[record.Operation.Domain] = append(byDomain[record.Operation.Domain], record)
	}
	var domains []string
	for domain := range byDomain {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	for _, domain := range domains {
		fmt.Fprintf(&b, "## %s\n\n", domain)
		fmt.Fprintf(&b, "| Status | Method | Path | Operation | MCP | Grant | Rationale |\n")
		fmt.Fprintf(&b, "|---|---|---|---|---|---|---|\n")
		for _, record := range byDomain[domain] {
			mcp := string(record.MappingType)
			if record.MCPName != "" {
				mcp += ": `" + record.MCPName + "`"
			}
			if record.ResourceURI != "" {
				mcp += ": `" + record.ResourceURI + "`"
			}
			fmt.Fprintf(&b, "| %s | %s | `%s` | `%s` | %s | `%s` | %s |\n", record.Status, record.Operation.Method, record.Operation.Path, record.Operation.OperationID, mcp, record.GrantPermission, record.Rationale)
		}
		fmt.Fprintln(&b)
	}

	return os.WriteFile(path, b.Bytes(), 0o644)
}

func WriteBacklog(path string, report Report) error {
	var b bytes.Buffer
	fmt.Fprintln(&b, "# MCP Parity Backlog")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Unimplemented Tailscale OpenAPI operations grouped by domain.")
	fmt.Fprintln(&b)

	byDomain := map[string][]Record{}
	for _, record := range report.Operations {
		if record.Status == StatusGap {
			byDomain[record.Operation.Domain] = append(byDomain[record.Operation.Domain], record)
		}
	}
	var domains []string
	for domain := range byDomain {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	for _, domain := range domains {
		fmt.Fprintf(&b, "## %s\n\n", domain)
		for _, record := range byDomain[domain] {
			fmt.Fprintf(&b, "- [ ] `%s %s` (`%s`) -> %s\n", record.Operation.Method, record.Operation.Path, record.Operation.OperationID, record.MappingType)
		}
		fmt.Fprintln(&b)
	}
	return os.WriteFile(path, b.Bytes(), 0o644)
}
