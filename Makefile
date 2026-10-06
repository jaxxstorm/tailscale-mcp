OPENAPI_SOURCE_URL ?= https://api.tailscale.com/api/v2?outputOpenapiSchema=true
OPENAPI_SCHEMA ?= tools/coverage/tailscale-v2-openapi.yaml
OPENAPI_METADATA ?= tools/coverage/snapshot-metadata.yaml
APERTURE_OPENAPI_SOURCE_URL ?= http://ai/aperture/openapi.json
APERTURE_OPENAPI_SCHEMA ?= tools/aperture/openapi.json
APERTURE_OPENAPI_METADATA ?= tools/aperture/snapshot-metadata.yaml

.PHONY: coverage openapi-refresh aperture-openapi-refresh test verify

openapi-refresh:
	go run ./tools/coverage/cmd/openapirefresh \
		--source-url "$(OPENAPI_SOURCE_URL)" \
		--schema-out "$(OPENAPI_SCHEMA)" \
		--metadata-out "$(OPENAPI_METADATA)"

aperture-openapi-refresh:
	go run ./tools/aperture/cmd/aperture-openapi-refresh \
		--source-url "$(APERTURE_OPENAPI_SOURCE_URL)" \
		--schema-out "$(APERTURE_OPENAPI_SCHEMA)" \
		--metadata-out "$(APERTURE_OPENAPI_METADATA)"

coverage:
	go run ./tools/coverage/cmd/mcpcoverage

test:
	go test ./...

verify: test coverage
