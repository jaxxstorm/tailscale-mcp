package readapi

type ParameterLocation string

const (
	PathParam  ParameterLocation = "path"
	QueryParam ParameterLocation = "query"
)

type Parameter struct {
	Name        string
	Location    ParameterLocation
	Description string
	Required    bool
}

type Endpoint struct {
	OperationID string
	ToolName    string
	Summary     string
	Method      string
	Path        string
	Parameters  []Parameter
	Body        bool
	ReadLike    bool
	Confirm     string
}

type Resource struct {
	OperationID string
	URI         string
	Name        string
	Endpoint    Endpoint
}

type ResourceTemplate struct {
	OperationID string
	URI         string
	Name        string
	Endpoint    Endpoint
}

func RequiredPath(name, description string) Parameter {
	return Parameter{Name: name, Location: PathParam, Description: description, Required: true}
}

func Query(name, description string, required bool) Parameter {
	return Parameter{Name: name, Location: QueryParam, Description: description, Required: required}
}
