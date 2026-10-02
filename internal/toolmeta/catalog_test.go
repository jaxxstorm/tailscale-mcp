package toolmeta

import (
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func TestCatalogSelectorsAndOwnership(t *testing.T) {
	input := []Tool{{"dns_read", "dns", true}, {"get_but_mutates", "dns", false}, {"device_read", "devices", true}}
	c, err := New(input)
	if err != nil {
		t.Fatal(err)
	}
	input[0].Group = "corrupted"
	copy := c.Tools()
	copy[0].Group = "corrupted"
	for _, tc := range []struct {
		selectors []string
		name      string
		want      bool
	}{
		{[]string{"dns_read"}, "dns_read", true},
		{[]string{"*"}, "get_but_mutates", true},
		{[]string{"*"}, "absent", false},
		{[]string{"read:*"}, "get_but_mutates", false},
		{[]string{"read:*"}, "device_read", true},
		{[]string{"group:dns"}, "get_but_mutates", true},
		{[]string{"group:dns:read"}, "get_but_mutates", false},
		{[]string{"group:dns:read"}, "dns_read", true},
		{[]string{"read:*", "group:dns"}, "get_but_mutates", true},
		{[]string{"read:*", "group:dns"}, "device_read", true},
		{[]string{"", "group:unknown", "group:*", "dns_*", "group:dns:write", "read:dns_read"}, "dns_read", false},
	} {
		if got := c.Allows(tc.selectors, tc.name); got != tc.want {
			t.Errorf("Allows(%v, %s) = %v", tc.selectors, tc.name, got)
		}
	}
	for _, invalid := range [][]Tool{{{"", "dns", true}}, {{"name", "", true}}, {{"a", "dns", true}, {"a", "dns", true}}, {{"a", "dns:read", true}}} {
		if _, err := New(invalid); err == nil {
			t.Errorf("accepted invalid metadata: %v", invalid)
		}
	}
	other, _ := New([]Tool{{"other", "dns", true}})
	if other.Allows([]string{"*"}, "dns_read") || !c.Allows([]string{"group:dns"}, "dns_read") {
		t.Fatal("catalogs share state")
	}
}

func TestCatalogRegistrationValidation(t *testing.T) {
	c, _ := New([]Tool{{"a", "dns", true}})
	for _, registered := range []map[string]*server.ServerTool{
		{},
		{"other": {Tool: mcp.NewTool("other", mcp.WithReadOnlyHintAnnotation(true))}},
		{"a": {Tool: mcp.NewTool("a")}},
		{"a": {Tool: mcp.NewTool("a", mcp.WithReadOnlyHintAnnotation(false))}},
	} {
		if c.Validate(registered) == nil {
			t.Fatal("accepted inconsistent registration")
		}
	}
	if err := c.Validate(map[string]*server.ServerTool{"a": {Tool: mcp.NewTool("a", mcp.WithReadOnlyHintAnnotation(true))}}); err != nil {
		t.Fatal(err)
	}
}
