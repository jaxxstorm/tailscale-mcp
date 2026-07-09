package mcpcoverage

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type openAPIDocument struct {
	Paths map[string]map[string]any `json:"paths" yaml:"paths"`
}

type openAPIOperation struct {
	OperationID string   `json:"operationId" yaml:"operationId"`
	Summary     string   `json:"summary" yaml:"summary"`
	Tags        []string `json:"tags" yaml:"tags"`
}

func LoadOpenAPI(path string) ([]Operation, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var doc openAPIDocument
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse OpenAPI document: %w", err)
	}

	var ops []Operation
	for path, methods := range doc.Paths {
		for method, raw := range methods {
			method = strings.ToUpper(method)
			if !isHTTPMethod(method) {
				continue
			}

			opBytes, err := yaml.Marshal(raw)
			if err != nil {
				return nil, fmt.Errorf("marshal operation %s %s: %w", method, path, err)
			}
			var op openAPIOperation
			if err := yaml.Unmarshal(opBytes, &op); err != nil {
				return nil, fmt.Errorf("parse operation %s %s: %w", method, path, err)
			}

			operationID := op.OperationID
			if operationID == "" {
				operationID = fallbackOperationID(method, path)
			}
			domain := "unknown"
			if len(op.Tags) > 0 && op.Tags[0] != "" {
				domain = op.Tags[0]
			}
			ops = append(ops, Operation{
				OperationID: operationID,
				Method:      method,
				Path:        path,
				Domain:      domain,
				Summary:     op.Summary,
			})
		}
	}

	sort.Slice(ops, func(i, j int) bool {
		if ops[i].Domain != ops[j].Domain {
			return ops[i].Domain < ops[j].Domain
		}
		if ops[i].Path != ops[j].Path {
			return ops[i].Path < ops[j].Path
		}
		return ops[i].Method < ops[j].Method
	})

	return ops, nil
}

func isHTTPMethod(method string) bool {
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

func fallbackOperationID(method, path string) string {
	return snake(method + " " + strings.ReplaceAll(path, "{", " by "))
}
