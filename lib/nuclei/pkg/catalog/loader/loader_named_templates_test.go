package loader

import (
	"embed"
	"fmt"
	"sync"
	"testing"
)

func TestTemplateNameSelectionFiltersBeforeParsing(t *testing.T) {
	paths := make([]string, 0, 2420)
	for i := 0; i < 2419; i++ {
		paths = append(paths, fmt.Sprintf("config/pocs/unrelated-%04d.yaml", i))
	}
	paths = append(paths, "config/pocs/CVE-2024-1234.yaml")

	selection := newTemplateNameSelection([]string{"cve-2024-1234.yaml"}, false)
	var matched []string
	for _, path := range paths {
		if selection.matchesPath(path) {
			matched = append(matched, path)
		}
	}

	if len(matched) != 1 || matched[0] != "config/pocs/CVE-2024-1234.yaml" {
		t.Fatalf("expected one candidate template, got %v", matched)
	}
}

func TestTemplateNameSelectionSupportsPathsAndTags(t *testing.T) {
	selection := newTemplateNameSelection([]string{
		`http\cves\CVE-2024-1234.yaml`,
		"Tags@Nginx.yaml",
	}, false)

	if !selection.matchesPath("/tmp/pocs/http/cves/CVE-2024-1234.yaml") {
		t.Fatal("expected Windows-style selector to match slash-normalized path")
	}
	if !selection.matchesTags([]string{"http", "nginx"}) {
		t.Fatal("expected Tags@ selector to match template metadata")
	}
	if selection.matchesTags([]string{"apache"}) {
		t.Fatal("unexpected tag match")
	}
}

func TestTemplateNameSelectionFuzzySearch(t *testing.T) {
	selection := newTemplateNameSelection([]string{"spring-cloud"}, true)
	if !selection.matchesPath("config/pocs/http/spring-cloud-function-rce.yaml") {
		t.Fatal("expected fuzzy path match")
	}
	if selection.matchesPath("config/pocs/http/struts-rce.yaml") {
		t.Fatal("unexpected fuzzy path match")
	}
}

func TestNamedTemplatesCacheKeyIsOrderIndependent(t *testing.T) {
	first := namedTemplatesCacheKey(
		[]string{"b.yaml", "a.yaml"},
		[]string{"dos", "intrusive"},
		[]string{"high", "critical"},
		false,
	)
	second := namedTemplatesCacheKey(
		[]string{"a.yaml", "b.yaml"},
		[]string{"intrusive", "dos"},
		[]string{"critical", "high"},
		false,
	)
	if first != second {
		t.Fatalf("cache key depends on input order: %q != %q", first, second)
	}
}

func TestLoadTemplatesWithNamesConcurrentEmptySelection(t *testing.T) {
	store := &Store{}
	const workers = 64
	var wait sync.WaitGroup
	wait.Add(workers)

	for i := 0; i < workers; i++ {
		go func() {
			defer wait.Done()
			result := store.LoadTemplatesWithNames(embed.FS{}, []string{"config/pocs/invalid.yaml"}, nil, nil, nil, false)
			if len(result) != 0 {
				t.Errorf("expected no templates, got %d", len(result))
			}
		}()
	}
	wait.Wait()

	if len(store.namedTemplatesCache) != 1 {
		t.Fatalf("expected one cached selection, got %d", len(store.namedTemplatesCache))
	}
}
