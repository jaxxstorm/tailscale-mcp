package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	mcpcoverage "github.com/jaxxstorm/tailscale-mcp/tools/coverage"
)

func main() {
	openAPIPath := flag.String("openapi", "tools/coverage/tailscale-v2-openapi.yaml", "path to vendored Tailscale OpenAPI YAML or JSON")
	exclusionsPath := flag.String("exclusions", "tools/coverage/exclusions.yaml", "path to reviewed exclusions YAML")
	outDir := flag.String("out", "coverage", "directory for generated coverage artifacts")
	baselinePath := flag.String("baseline", "coverage/mcp-coverage-baseline.json", "path to baseline coverage JSON")
	flag.Parse()

	ops, err := mcpcoverage.LoadOpenAPI(*openAPIPath)
	if err != nil {
		log.Fatal(err)
	}
	exclusions, err := mcpcoverage.LoadExclusions(*exclusionsPath)
	if err != nil {
		log.Fatal(err)
	}
	report, err := mcpcoverage.BuildReport(*openAPIPath, ops, mcpcoverage.CurrentMappings(), exclusions)
	if err != nil {
		log.Fatal(err)
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		log.Fatal(err)
	}
	if err := mcpcoverage.WriteJSON(filepath.Join(*outDir, "mcp-coverage.json"), report); err != nil {
		log.Fatal(err)
	}
	if err := mcpcoverage.WriteMarkdown(filepath.Join(*outDir, "mcp-coverage.md"), report); err != nil {
		log.Fatal(err)
	}
	if err := mcpcoverage.WriteBacklog(filepath.Join(*outDir, "parity-backlog.md"), report); err != nil {
		log.Fatal(err)
	}
	if err := mcpcoverage.WriteDiff(filepath.Join(*outDir, "mcp-coverage-diff.md"), report, *baselinePath); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("MCP coverage: %d total, %d implemented, %d gaps, %d excluded\n", report.Summary.Total, report.Summary.Implemented, report.Summary.Gaps, report.Summary.Excluded)
}
