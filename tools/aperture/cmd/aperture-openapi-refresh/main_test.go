package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func cachedSchema(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("../../openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCachedContract(t *testing.T) {
	schema := cachedSchema(t)
	data, err := os.ReadFile("../../snapshot-metadata.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var metadata snapshotMetadata
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&metadata); err != nil {
		t.Fatal(err)
	}
	date, err := time.Parse(time.DateOnly, metadata.RetrievedAt)
	if err != nil {
		t.Fatal(err)
	}
	want, err := buildSnapshotMetadata(schema, "http://ai/aperture/openapi.json", "openapi.json", date)
	if err != nil {
		t.Fatal(err)
	}
	if metadata != want {
		t.Fatalf("metadata drift:\n got: %+v\nwant: %+v", metadata, want)
	}
	if metadata.OpenAPIVersion != "3.1.0" || metadata.APIVersion != "0" || metadata.APITitle != "Aperture API" || metadata.PathCount != 4 || metadata.OperationCount != 5 {
		t.Fatalf("review changed API identity/counts: %+v", metadata)
	}
	var doc openAPIDocument
	if err := json.Unmarshal(schema, &doc); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for path, methods := range doc.Paths {
		for method, raw := range methods {
			switch method {
			case "get", "put", "post", "delete", "options", "head", "patch", "trace":
			default:
				continue
			}
			var op struct {
				ID string `json:"operationId"`
			}
			if err := json.Unmarshal(raw, &op); err != nil {
				t.Fatal(err)
			}
			got[strings.ToUpper(method)+" "+path] = op.ID
		}
	}
	wantOps := map[string]string{
		"GET /config":           "get-config",
		"PUT /config":           "set-config",
		"POST /config:validate": "validate-config",
		"GET /pricing":          "get-pricing",
		"GET /pricing/{model}":  "get-model-pricing",
	}
	if !reflect.DeepEqual(got, wantOps) {
		t.Fatalf("review operation inventory drift: got %v, want %v", got, wantOps)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type failedReader struct{}

func (failedReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestRefreshPreservesCache(t *testing.T) {
	schema := cachedSchema(t)
	tests := []struct {
		name   string
		status int
		body   io.Reader
		err    error
	}{
		{name: "unreachable", err: errors.New("offline")},
		{name: "HTTP error", status: 503, body: strings.NewReader("unavailable")},
		{name: "redirect", status: 302, body: strings.NewReader("")},
		{name: "truncated download", status: 200, body: io.MultiReader(bytes.NewReader(schema[:100]), failedReader{})},
		{name: "oversized", status: 200, body: io.MultiReader(bytes.NewReader(schema), strings.NewReader(strings.Repeat(" ", maxSchemaBytes)))},
		{name: "invalid JSON", status: 200, body: strings.NewReader("<html>not a schema</html>")},
		{name: "trailing JSON", status: 200, body: io.MultiReader(bytes.NewReader(schema), strings.NewReader("{}"))},
		{name: "wrong identity", status: 200, body: bytes.NewReader(bytes.Replace(schema, []byte(`"Aperture API"`), []byte(`"Other API"`), 1))},
		{name: "wrong OpenAPI", status: 200, body: bytes.NewReader(bytes.Replace(schema, []byte(`"3.1.0"`), []byte(`"2.0"`), 1))},
		{name: "missing ID", status: 200, body: bytes.NewReader(bytes.Replace(schema, []byte(`"get-config"`), []byte(`""`), 1))},
		{name: "duplicate ID", status: 200, body: bytes.NewReader(bytes.Replace(schema, []byte(`"get-config"`), []byte(`"set-config"`), 1))},
		{name: "empty paths", status: 200, body: strings.NewReader(`{"openapi":"3.1.0","info":{"title":"Aperture API","version":"0"},"paths":{}}`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			schemaPath, metadataPath := filepath.Join(dir, "openapi.json"), filepath.Join(dir, "metadata.yaml")
			writeTestFile(t, schemaPath, schema)
			writeTestFile(t, metadataPath, []byte("original metadata"))
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method != "GET" || r.URL.String() != sourceURL {
					t.Fatalf("unexpected request: %s %s", r.Method, r.URL)
				}
				if tt.err != nil {
					return nil, tt.err
				}
				return &http.Response{StatusCode: tt.status, Body: io.NopCloser(tt.body), Header: make(http.Header)}, nil
			})}
			if err := refresh(client, sourceURL, schemaPath, metadataPath, time.Now()); err == nil {
				t.Fatal("expected refresh failure")
			}
			assertFile(t, schemaPath, schema)
			assertFile(t, metadataPath, []byte("original metadata"))
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 2 {
				t.Fatalf("temporary files leaked: %v, %v", entries, err)
			}
		})
	}
}

func TestRefreshSuccess(t *testing.T) {
	// Accept structurally valid additions; the independent cached inventory
	// test and production mapping tests require review after such a refresh.
	var doc map[string]any
	if err := json.Unmarshal(cachedSchema(t), &doc); err != nil {
		t.Fatal(err)
	}
	doc["paths"].(map[string]any)["/new"] = map[string]any{"get": map[string]any{
		"operationId": "new-operation", "responses": map[string]any{"200": map[string]any{"description": "OK"}},
	}}
	schema, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprintf("existing=%t", existing), func(t *testing.T) {
			dir := t.TempDir()
			schemaPath, metadataPath := filepath.Join(dir, "openapi.json"), filepath.Join(dir, "metadata.yaml")
			if existing {
				writeTestFile(t, schemaPath, []byte("old schema"))
				writeTestFile(t, metadataPath, []byte("old metadata"))
			}
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(schema))}, nil
			})}
			now := time.Date(2026, 10, 7, 1, 0, 0, 0, time.FixedZone("east", 2*60*60))
			if err := refresh(client, sourceURL, schemaPath, metadataPath, now); err != nil {
				t.Fatal(err)
			}
			assertFile(t, schemaPath, schema)
			data, err := os.ReadFile(metadataPath)
			if err != nil {
				t.Fatal(err)
			}
			var metadata snapshotMetadata
			if err := yaml.Unmarshal(data, &metadata); err != nil {
				t.Fatal(err)
			}
			if metadata.SHA256 != fmt.Sprintf("%x", sha256.Sum256(schema)) || metadata.SourceURL != sourceURL || metadata.RetrievedAt != "2026-10-06" || metadata.Snapshot != "openapi.json" || metadata.OperationCount != 6 || metadata.PathCount != 5 {
				t.Fatalf("incorrect refreshed metadata: %+v", metadata)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 2 {
				t.Fatalf("temporary files leaked: %v, %v", entries, err)
			}
		})
	}
}

func TestInvalidInventory(t *testing.T) {
	for name, paths := range map[string]string{
		"null paths":        `null`,
		"invalid path":      `{"config":{"get":{"operationId":"get-config","responses":{"200":{}}}}}`,
		"null path item":    `{"/config":null}`,
		"null operation":    `{"/config":{"get":null}}`,
		"invalid operation": `{"/config":{"get":[]}}`,
		"missing responses": `{"/config":{"get":{"operationId":"get-config"}}}`,
		"unknown method":    `{"/config":{"fetch":{"operationId":"get-config","responses":{"200":{}}}}}`,
		"reference only":    `{"/config":{"$ref":"#/components/pathItems/config"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			schema := []byte(`{"openapi":"3.1.0","info":{"title":"Aperture API","version":"0"},"paths":` + paths + `}`)
			if _, err := buildSnapshotMetadata(schema, sourceURL, "openapi.json", time.Now()); err == nil {
				t.Fatal("expected invalid inventory to be rejected")
			}
		})
	}
}

func TestInvalidRefreshOptions(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid options must fail before download")
		return nil, errors.New("unexpected download")
	})}
	for _, source := range []string{"", ":bad", "file:///tmp/schema", "http:///schema", "http://user:password@ai/schema", "http://ai/schema#fragment"} {
		if err := refresh(client, source, "schema.json", "metadata.yaml", time.Now()); err == nil {
			t.Errorf("accepted invalid source %q", source)
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "cache")
	writeTestFile(t, path, []byte("original"))
	if err := refresh(client, sourceURL, path, path, time.Now()); err == nil {
		t.Fatal("accepted same output paths")
	}
	if err := refresh(client, sourceURL, path, dir, time.Now()); err == nil {
		t.Fatal("accepted directory output")
	}
	assertFile(t, path, []byte("original"))
}

func TestMetadataStagingFailurePreservesSchema(t *testing.T) {
	dir := t.TempDir()
	schemaPath := filepath.Join(dir, "openapi.json")
	writeTestFile(t, schemaPath, []byte("original schema"))
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(cachedSchema(t)))}, nil
	})}
	if err := refresh(client, sourceURL, schemaPath, filepath.Join(dir, "missing", "metadata.yaml"), time.Now()); err == nil {
		t.Fatal("expected staging failure")
	}
	assertFile(t, schemaPath, []byte("original schema"))
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary files leaked: %v, %v", entries, err)
	}
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertFile(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("unexpected contents of %s", path)
	}
}
