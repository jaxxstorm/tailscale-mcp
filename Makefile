OPENAPI_SOURCE_URL ?= https://api.tailscale.com/api/v2?outputOpenapiSchema=true
OPENAPI_SCHEMA ?= tools/coverage/tailscale-v2-openapi.yaml
OPENAPI_METADATA ?= tools/coverage/snapshot-metadata.yaml

.PHONY: coverage openapi-refresh test verify

openapi-refresh:
	go run ./tools/coverage/cmd/openapirefresh \
		--source-url "$(OPENAPI_SOURCE_URL)" \
		--schema-out "$(OPENAPI_SCHEMA)" \
		--metadata-out "$(OPENAPI_METADATA)"

coverage:
	go run ./tools/coverage/cmd/mcpcoverage

test:
	go test ./...

verify: test coverage
