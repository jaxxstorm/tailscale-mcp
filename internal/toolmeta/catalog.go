// Package toolmeta defines immutable, server-owned authorization metadata.
package toolmeta

import (
	"fmt"
	"sort"
	"strings"

	"github.com/mark3labs/mcp-go/server"
)

type Tool struct {
	Name     string `json:"name"`
	Group    string `json:"group"`
	ReadOnly bool   `json:"readOnly"`
}

type Catalog struct{ tools map[string]Tool }

func New(tools []Tool) (*Catalog, error) {
	c := &Catalog{tools: make(map[string]Tool, len(tools))}
	for _, tool := range tools {
		if strings.TrimSpace(tool.Name) == "" || strings.TrimSpace(tool.Group) == "" || strings.ContainsAny(tool.Group, ":* \t\n") {
			return nil, fmt.Errorf("incomplete tool metadata for %q", tool.Name)
		}
		if _, ok := c.tools[tool.Name]; ok {
			return nil, fmt.Errorf("duplicate tool metadata: %s", tool.Name)
		}
		c.tools[tool.Name] = tool
	}
	return c, nil
}

// Tools returns a sorted copy; callers cannot mutate catalog state.
func (c *Catalog) Tools() []Tool {
	tools := make([]Tool, 0, len(c.tools))
	for _, tool := range c.tools {
		tools = append(tools, tool)
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	return tools
}

func (c *Catalog) Allows(selectors []string, name string) bool {
	if c == nil {
		return false
	}
	tool, ok := c.tools[name]
	if !ok {
		return false
	}
	for _, selector := range selectors {
		if selector == name || selector == "*" || selector == "group:"+tool.Group ||
			(tool.ReadOnly && (selector == "read:*" || selector == "group:"+tool.Group+":read")) {
			return true
		}
	}
	return false
}

func (c *Catalog) Validate(registered map[string]*server.ServerTool) error {
	if len(registered) != len(c.tools) {
		return fmt.Errorf("tool registration/catalog size mismatch: %d/%d", len(registered), len(c.tools))
	}
	for name, registration := range registered {
		if registration == nil || registration.Tool.Name != name {
			return fmt.Errorf("invalid tool registration: %s", name)
		}
		tool, ok := c.tools[name]
		readOnly := registration.Tool.Annotations.ReadOnlyHint
		if !ok || readOnly == nil || *readOnly != tool.ReadOnly {
			return fmt.Errorf("tool registration/catalog metadata mismatch: %s", name)
		}
	}
	return nil
}
