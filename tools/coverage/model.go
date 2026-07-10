package mcpcoverage

import "strings"

const (
	MappingTool       MappingType = "tool"
	MappingResource   MappingType = "resource"
	MappingPrompt     MappingType = "prompt"
	MappingNone       MappingType = "none"
	StatusImplemented Status      = "implemented"
	StatusGap         Status      = "gap"
	StatusExcluded    Status      = "excluded"
	StatusPlanned     Status      = "planned"
)

type MappingType string

type Status string

type Operation struct {
	OperationID string `json:"operationId"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	Domain      string `json:"domain"`
	Summary     string `json:"summary,omitempty"`
}

type Mapping struct {
	OperationID     string      `json:"operationId"`
	Type            MappingType `json:"type"`
	Name            string      `json:"name,omitempty"`
	URI             string      `json:"uri,omitempty"`
	GrantPermission string      `json:"grantPermission,omitempty"`
	Rationale       string      `json:"rationale"`
	ReadOnly        bool        `json:"readOnly,omitempty"`
	Destructive     bool        `json:"destructive,omitempty"`
	Idempotent      bool        `json:"idempotent,omitempty"`
	Confirmation    string      `json:"confirmation,omitempty"`
}

type Exclusion struct {
	OperationID string `json:"operationId" yaml:"operationId"`
	Reason      string `json:"reason" yaml:"reason"`
	Notes       string `json:"notes,omitempty" yaml:"notes,omitempty"`
	FollowUp    string `json:"followUp,omitempty" yaml:"followUp,omitempty"`
}

type Record struct {
	Operation       Operation   `json:"operation"`
	MappingType     MappingType `json:"mappingType"`
	MCPName         string      `json:"mcpName,omitempty"`
	ResourceURI     string      `json:"resourceUri,omitempty"`
	GrantPermission string      `json:"grantPermission,omitempty"`
	Status          Status      `json:"status"`
	Rationale       string      `json:"rationale"`
	ExclusionReason string      `json:"exclusionReason,omitempty"`
	ExclusionNotes  string      `json:"exclusionNotes,omitempty"`
	FollowUp        string      `json:"followUp,omitempty"`
	ReadOnly        bool        `json:"readOnly,omitempty"`
	Destructive     bool        `json:"destructive,omitempty"`
	Idempotent      bool        `json:"idempotent,omitempty"`
	Confirmation    string      `json:"confirmation,omitempty"`
}

type Report struct {
	Source     string   `json:"source"`
	Operations []Record `json:"operations"`
	Summary    Summary  `json:"summary"`
}

type Summary struct {
	Total       int `json:"total"`
	Implemented int `json:"implemented"`
	Gaps        int `json:"gaps"`
	Excluded    int `json:"excluded"`
	Planned     int `json:"planned"`
}

func ToolName(action, object string) string {
	return snake(action + " " + object)
}

func ResourceURI(parts ...string) string {
	clean := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.Trim(part, "/")
		if part != "" {
			clean = append(clean, part)
		}
	}
	if len(clean) == 0 {
		return "tailscale://"
	}
	return "tailscale://" + strings.Join(clean, "/")
}

func ToolGrant(name string) string {
	return "tool:" + name
}

func ResourceGrant(uri string) string {
	return "resource:" + uri
}

func IsMutating(method string) bool {
	switch strings.ToUpper(method) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

func IsDestructive(method string, operationID string) bool {
	if strings.EqualFold(method, "DELETE") {
		return true
	}
	operationID = strings.ToLower(operationID)
	return strings.Contains(operationID, "delete") || strings.Contains(operationID, "expire") || strings.Contains(operationID, "revoke") || strings.Contains(operationID, "suspend") || strings.Contains(operationID, "rotate")
}

func ClassifyDefault(op Operation) MappingType {
	if IsMutating(op.Method) {
		return MappingTool
	}
	if strings.EqualFold(op.Method, "GET") && !strings.Contains(op.Path, "{") {
		return MappingResource
	}
	if strings.EqualFold(op.Method, "GET") {
		return MappingTool
	}
	return MappingNone
}

func ValidateMapping(op Operation, mapping Mapping) error {
	if IsMutating(op.Method) && mapping.Type == MappingResource {
		return ErrMutatingResource
	}
	return nil
}

func snake(s string) string {
	var b strings.Builder
	lastUnderscore := false
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastUnderscore = false
			continue
		}
		if !lastUnderscore && b.Len() > 0 {
			b.WriteByte('_')
			lastUnderscore = true
		}
	}
	return strings.Trim(b.String(), "_")
}
