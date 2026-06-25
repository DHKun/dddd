package nucleiadapter

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

func TestScanUsesSDKCallbackAndPreservesPackets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/first":
			fmt.Fprint(w, "first")
		case "/second":
			fmt.Fprint(w, "matched")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	templateDirectory := filepath.Join("testdata")

	callbacks := 0
	results, err := Scan(context.Background(), Config{
		TargetTemplates: map[string][]string{
			server.URL: {"sdk-adapter.yaml"},
		},
		TemplatePath: templateDirectory,
		Embedded: fstest.MapFS{
			"sdk-adapter.yaml": {Data: []byte(`id: sdk-adapter-embedded

info:
  name: Embedded Override Sentinel
  author: DHKun
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}/embedded"
    matchers:
      - type: status
        status:
          - 404
`)},
		},
		NoInteractsh: true,
		Callback: func(output.ResultEvent) {
			callbacks++
		},
	})
	if err != nil {
		t.Fatalf("Scan(): %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	if results[0].TemplateID != "sdk-adapter" {
		t.Fatalf("template id = %q, want external sdk-adapter", results[0].TemplateID)
	}
	if callbacks != 1 {
		t.Fatalf("callbacks = %d, want 1", callbacks)
	}
	if len(results[0].Packet) != 2 {
		t.Fatalf("packet count = %d, want 2", len(results[0].Packet))
	}
}
