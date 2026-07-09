package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var operationMethods = map[string]struct{}{
	"get":     {},
	"post":    {},
	"put":     {},
	"patch":   {},
	"delete":  {},
	"options": {},
	"head":    {},
	"trace":   {},
}

type openAPIDocument struct {
	OpenAPI string                    `yaml:"openapi"`
	Info    openAPIInfo               `yaml:"info"`
	Paths   map[string]map[string]any `yaml:"paths"`
}

type openAPIInfo struct {
	Version string `yaml:"version"`
}

type snapshotMetadata struct {
	SourceURL      string `yaml:"source_url"`
	FetchedAtUTC   string `yaml:"fetched_at_utc"`
	OpenAPIVersion string `yaml:"openapi_version"`
	APIVersion     string `yaml:"api_version"`
	PathCount      int    `yaml:"path_count"`
	OperationCount int    `yaml:"operation_count"`
	SHA256         string `yaml:"sha256"`
	SchemaFile     string `yaml:"schema_file"`
}

func main() {
	sourceURL := flag.String("source-url", "", "canonical OpenAPI source URL")
	schemaOut := flag.String("schema-out", "tools/coverage/tailscale-v2-openapi.yaml", "path for vendored OpenAPI schema")
	metadataOut := flag.String("metadata-out", "tools/coverage/snapshot-metadata.yaml", "path for snapshot metadata")
	flag.Parse()

	if *sourceURL == "" {
		fatalf("source-url is required")
	}

	schema, err := fetchSchema(*sourceURL)
	if err != nil {
		fatalf("fetch schema: %v", err)
	}

	metadata, err := buildSnapshotMetadata(schema, *sourceURL, *schemaOut, time.Now().UTC())
	if err != nil {
		fatalf("build snapshot metadata: %v", err)
	}

	metadataBytes, err := yaml.Marshal(metadata)
	if err != nil {
		fatalf("marshal snapshot metadata: %v", err)
	}

	if err := writeFiles(map[string][]byte{*schemaOut: schema, *metadataOut: metadataBytes}); err != nil {
		fatalf("write refreshed snapshot: %v", err)
	}
}

func fetchSchema(sourceURL string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, sourceURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("unexpected status %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	return io.ReadAll(resp.Body)
}

func buildSnapshotMetadata(schema []byte, sourceURL, schemaPath string, fetchedAt time.Time) (snapshotMetadata, error) {
	var doc openAPIDocument
	if err := yaml.Unmarshal(schema, &doc); err != nil {
		return snapshotMetadata{}, err
	}
	if doc.OpenAPI == "" {
		return snapshotMetadata{}, fmt.Errorf("schema missing openapi version")
	}
	if len(doc.Paths) == 0 {
		return snapshotMetadata{}, fmt.Errorf("schema missing paths")
	}

	sum := sha256.Sum256(schema)
	return snapshotMetadata{
		SourceURL:      sourceURL,
		FetchedAtUTC:   fetchedAt.Format(time.RFC3339),
		OpenAPIVersion: doc.OpenAPI,
		APIVersion:     doc.Info.Version,
		PathCount:      len(doc.Paths),
		OperationCount: countOperations(doc.Paths),
		SHA256:         hex.EncodeToString(sum[:]),
		SchemaFile:     filepath.Base(schemaPath),
	}, nil
}

func countOperations(paths map[string]map[string]any) int {
	total := 0
	for _, methods := range paths {
		for method := range methods {
			if _, ok := operationMethods[strings.ToLower(method)]; ok {
				total++
			}
		}
	}
	return total
}

func writeFiles(files map[string][]byte) error {
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	for _, path := range paths {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, files[path], 0o644); err != nil {
			return err
		}
	}
	return nil
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
