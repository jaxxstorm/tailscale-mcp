package mcpcoverage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

func WriteDiff(path string, current Report, baselinePath string) error {
	var b bytes.Buffer
	fmt.Fprintln(&b, "# MCP Coverage Diff")
	fmt.Fprintln(&b)

	if baselinePath == "" {
		fmt.Fprintln(&b, "No baseline configured.")
		return os.WriteFile(path, b.Bytes(), 0o644)
	}

	data, err := os.ReadFile(baselinePath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(&b, "Baseline `%s` does not exist yet.\n", baselinePath)
			return os.WriteFile(path, b.Bytes(), 0o644)
		}
		return err
	}

	var baseline Report
	if err := json.Unmarshal(data, &baseline); err != nil {
		return fmt.Errorf("parse baseline: %w", err)
	}

	base := recordsByID(baseline)
	curr := recordsByID(current)

	var newGaps, closedGaps, changed []string
	for id, record := range curr {
		old, ok := base[id]
		if !ok && record.Status == StatusGap {
			newGaps = append(newGaps, id)
			continue
		}
		if ok && old.Status != StatusGap && record.Status == StatusGap {
			newGaps = append(newGaps, id)
		}
		if ok && old.Status == StatusGap && record.Status != StatusGap {
			closedGaps = append(closedGaps, id)
		}
		if ok && (old.MappingType != record.MappingType || old.MCPName != record.MCPName || old.ResourceURI != record.ResourceURI) {
			changed = append(changed, id)
		}
	}

	writeList(&b, "New Gaps", newGaps)
	writeList(&b, "Closed Gaps", closedGaps)
	writeList(&b, "Changed Mappings", changed)
	return os.WriteFile(path, b.Bytes(), 0o644)
}

func recordsByID(report Report) map[string]Record {
	result := make(map[string]Record, len(report.Operations))
	for _, record := range report.Operations {
		result[record.Operation.OperationID] = record
	}
	return result
}

func writeList(b *bytes.Buffer, title string, items []string) {
	fmt.Fprintf(b, "## %s\n\n", title)
	if len(items) == 0 {
		fmt.Fprintln(b, "None.")
		fmt.Fprintln(b)
		return
	}
	for _, item := range items {
		fmt.Fprintf(b, "- `%s`\n", item)
	}
	fmt.Fprintln(b)
}
