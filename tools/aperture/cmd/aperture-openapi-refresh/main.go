package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const sourceURL = "http://ai/aperture/openapi.json"
const maxSchemaBytes = 16 << 20

type openAPIDocument struct {
	OpenAPI string `json:"openapi"`
	Info    struct {
		Title   string `json:"title"`
		Version string `json:"version"`
	} `json:"info"`
	Paths map[string]map[string]json.RawMessage `json:"paths"`
}

type snapshotMetadata struct {
	SourceURL      string `yaml:"source_url"`
	RetrievedAt    string `yaml:"retrieved_at"`
	Snapshot       string `yaml:"snapshot"`
	SHA256         string `yaml:"sha256"`
	OpenAPIVersion string `yaml:"openapi_version"`
	APITitle       string `yaml:"api_title"`
	APIVersion     string `yaml:"api_version"`
	OperationCount int    `yaml:"operation_count"`
	PathCount      int    `yaml:"path_count"`
	Notes          string `yaml:"notes"`
}

func main() {
	source := flag.String("source-url", sourceURL, "tailnet OpenAPI source URL (requires connectivity)")
	schema := flag.String("schema-out", "tools/aperture/openapi.json", "path for cached OpenAPI JSON")
	metadata := flag.String("metadata-out", "tools/aperture/snapshot-metadata.yaml", "path for snapshot metadata")
	flag.Parse()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if err := refresh(client, *source, *schema, *metadata, time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func buildSnapshotMetadata(schema []byte, source, schemaPath string, now time.Time) (snapshotMetadata, error) {
	var doc openAPIDocument
	if err := json.Unmarshal(schema, &doc); err != nil {
		return snapshotMetadata{}, fmt.Errorf("parse OpenAPI JSON: %w", err)
	}
	if doc.OpenAPI != "3.1.0" || doc.Info.Title != "Aperture API" || strings.TrimSpace(doc.Info.Version) == "" {
		return snapshotMetadata{}, fmt.Errorf("expected Aperture API OpenAPI 3.1.0 with a nonempty API version")
	}
	if len(doc.Paths) == 0 {
		return snapshotMetadata{}, fmt.Errorf("schema has no paths")
	}
	ids := make(map[string]bool)
	for path, methods := range doc.Paths {
		if !strings.HasPrefix(path, "/") {
			return snapshotMetadata{}, fmt.Errorf("invalid path %q", path)
		}
		count := 0
		for method, raw := range methods {
			switch method {
			case "get", "put", "post", "delete", "options", "head", "patch", "trace":
			default:
				if method == "parameters" || method == "summary" || method == "description" || method == "servers" || strings.HasPrefix(method, "x-") {
					continue
				}
				return snapshotMetadata{}, fmt.Errorf("unsupported path field %q at %s", method, path)
			}
			var op struct {
				ID        string                     `json:"operationId"`
				Responses map[string]json.RawMessage `json:"responses"`
			}
			if err := json.Unmarshal(raw, &op); err != nil {
				return snapshotMetadata{}, fmt.Errorf("invalid operation %s %s: %w", method, path, err)
			}
			if strings.TrimSpace(op.ID) == "" || ids[op.ID] || len(op.Responses) == 0 {
				return snapshotMetadata{}, fmt.Errorf("operation %s %s requires a unique operationId and responses", method, path)
			}
			ids[op.ID] = true
			count++
		}
		if count == 0 {
			return snapshotMetadata{}, fmt.Errorf("path %s has no operations", path)
		}
	}
	return snapshotMetadata{
		SourceURL: source, RetrievedAt: now.UTC().Format(time.DateOnly),
		Snapshot: filepath.Base(schemaPath), SHA256: fmt.Sprintf("%x", sha256.Sum256(schema)),
		OpenAPIVersion: doc.OpenAPI, APITitle: doc.Info.Title, APIVersion: doc.Info.Version,
		OperationCount: len(ids), PathCount: len(doc.Paths),
		Notes: "Tailnet-only source. Refresh explicitly while connected; builds and tests use the cached snapshot.",
	}, nil
}

func refresh(client *http.Client, source, schemaPath, metadataPath string, now time.Time) error {
	u, err := url.Parse(source)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("source must be an HTTP(S) URL without userinfo or fragment")
	}
	schemaPath, err = filepath.Abs(schemaPath)
	if err != nil {
		return err
	}
	metadataPath, err = filepath.Abs(metadataPath)
	if err != nil {
		return err
	}
	if schemaPath == metadataPath {
		return fmt.Errorf("schema and metadata paths must differ")
	}
	for _, path := range []string{schemaPath, metadataPath} {
		info, err := os.Lstat(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err == nil && !info.Mode().IsRegular() {
			return fmt.Errorf("output must be a regular file: %s", path)
		}
	}
	req, err := http.NewRequest(http.MethodGet, source, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download schema: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download schema: HTTP %d", resp.StatusCode)
	}
	candidate, err := os.CreateTemp(filepath.Dir(schemaPath), ".aperture-download-*")
	if err != nil {
		return err
	}
	defer os.Remove(candidate.Name())
	n, copyErr := io.Copy(candidate, io.LimitReader(resp.Body, maxSchemaBytes+1))
	closeErr := candidate.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return fmt.Errorf("download schema: %w", err)
	}
	if n > maxSchemaBytes {
		return fmt.Errorf("schema exceeds %d bytes", maxSchemaBytes)
	}
	schema, err := os.ReadFile(candidate.Name())
	if err != nil {
		return err
	}
	metadata, err := buildSnapshotMetadata(schema, source, schemaPath, now)
	if err != nil {
		return err
	}
	metadataBytes, err := yaml.Marshal(metadata)
	if err != nil {
		return err
	}
	metadataTemp, err := stageFile(metadataPath, metadataBytes)
	if err != nil {
		return err
	}
	defer os.Remove(metadataTemp)
	// Two renames cannot be atomic as a pair. Keep a staged backup to restore
	// the schema if the metadata rename fails; neither output is truncated.
	backup := ""
	oldSchema, err := os.ReadFile(schemaPath)
	if err == nil {
		backup, err = stageFile(schemaPath, oldSchema)
		if err != nil {
			return err
		}
		defer os.Remove(backup)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Chmod(candidate.Name(), 0o644); err != nil {
		return err
	}
	if err := os.Rename(candidate.Name(), schemaPath); err != nil {
		return err
	}
	if err := os.Rename(metadataTemp, metadataPath); err != nil {
		var rollbackErr error
		if backup != "" {
			rollbackErr = os.Rename(backup, schemaPath)
		} else {
			rollbackErr = os.Remove(schemaPath)
		}
		return errors.Join(fmt.Errorf("replace metadata: %w", err), rollbackErr)
	}
	return nil
}

func stageFile(path string, data []byte) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(path), ".aperture-stage-*")
	if err != nil {
		return "", err
	}
	_, writeErr := f.Write(data)
	modeErr := f.Chmod(0o644)
	closeErr := f.Close()
	if err := errors.Join(writeErr, modeErr, closeErr); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}
