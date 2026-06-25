package nuclei

import (
	"testing"
	"testing/fstest"
)

func TestGroupTargetsByTemplates(t *testing.T) {
	groups := groupTargetsByTemplates(map[string][]string{
		"https://b.example": {"b.yaml", "a.yaml", "a.yaml"},
		"https://a.example": {"a.yaml", "b.yaml"},
		"https://c.example": {"c.yaml"},
	}, "")

	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2", len(groups))
	}
	if len(groups[0].targets) != 2 {
		t.Fatalf("first group targets = %v", groups[0].targets)
	}
	if groups[0].targets[0] != "https://a.example" || groups[0].targets[1] != "https://b.example" {
		t.Fatalf("first group targets = %v", groups[0].targets)
	}
}

func TestEmbeddedTemplatePaths(t *testing.T) {
	paths, err := embeddedTemplatePaths(fstest.MapFS{
		"config/pocs/a.yaml": {Data: []byte("a")},
		"config/pocs/b.yml":  {Data: []byte("b")},
		"config/pocs/c.txt":  {Data: []byte("c")},
	})
	if err != nil {
		t.Fatalf("embeddedTemplatePaths(): %v", err)
	}
	if len(paths) != 2 || paths[0] != "config/pocs/a.yaml" || paths[1] != "config/pocs/b.yml" {
		t.Fatalf("paths = %v", paths)
	}
}

func TestGroupTargetsByTemplatesSearch(t *testing.T) {
	groups := groupTargetsByTemplates(map[string][]string{
		"https://b.example": {"b.yaml"},
		"https://a.example": {"a.yaml"},
	}, "spring")
	if len(groups) != 1 {
		t.Fatalf("groups = %d, want 1", len(groups))
	}
	if len(groups[0].templates) != 1 || groups[0].templates[0] != "spring" {
		t.Fatalf("templates = %v", groups[0].templates)
	}
}
