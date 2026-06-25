package common

import (
	"os"
	"path/filepath"
	"testing"

	"dddd/structs"
)

func TestReadWorkFlowDBLoadModes(t *testing.T) {
	oldConfig := structs.GlobalConfig
	oldWorkFlowDB := structs.WorkFlowDB
	oldEmbedPocs := structs.GlobalEmbedPocs
	t.Cleanup(func() {
		structs.GlobalConfig = oldConfig
		structs.WorkFlowDB = oldWorkFlowDB
		structs.GlobalEmbedPocs = oldEmbedPocs
	})

	workflowPath := filepath.Join(t.TempDir(), "custom-workflow.yaml")
	workflowData := []byte(`External-Test:
  type:
    - root
  pocs:
    - external-test-poc
`)
	if err := os.WriteFile(workflowPath, workflowData, 0600); err != nil {
		t.Fatalf("write workflow fixture: %v", err)
	}
	structs.GlobalConfig.WorkflowYamlPath = workflowPath

	t.Run("merge embedded and external", func(t *testing.T) {
		structs.GlobalConfig.ExternalPocOnly = false
		ReadWorkFlowDB()

		if _, ok := structs.WorkFlowDB["Liferay"]; !ok {
			t.Fatal("missing embedded workflow entry Liferay")
		}
		external, ok := structs.WorkFlowDB["External-Test"]
		if !ok {
			t.Fatal("missing external workflow entry from WorkflowYamlPath")
		}
		if !external.RootType || len(external.PocsName) != 1 || external.PocsName[0] != "external-test-poc" {
			t.Fatalf("external workflow entry = %#v", external)
		}
	})

	t.Run("external only", func(t *testing.T) {
		structs.GlobalConfig.ExternalPocOnly = true
		ReadWorkFlowDB()

		if _, ok := structs.WorkFlowDB["Liferay"]; ok {
			t.Fatal("found embedded workflow entry in external-only mode")
		}
		if len(structs.WorkFlowDB) != 1 {
			t.Fatalf("workflow count = %d, want 1", len(structs.WorkFlowDB))
		}
		if _, ok := structs.WorkFlowDB["External-Test"]; !ok {
			t.Fatal("missing external workflow entry")
		}
	})
}

func TestConfigurePocSources(t *testing.T) {
	oldConfig := structs.GlobalConfig
	oldEmbedPocs := structs.GlobalEmbedPocs
	t.Cleanup(func() {
		structs.GlobalConfig = oldConfig
		structs.GlobalEmbedPocs = oldEmbedPocs
	})

	structs.GlobalConfig.ExternalPocOnly = false
	configurePocSources()
	if _, err := structs.GlobalEmbedPocs.ReadFile("config/pocs/3cx-management-console.yaml"); err != nil {
		t.Fatalf("read embedded poc in default mode: %v", err)
	}

	structs.GlobalConfig.ExternalPocOnly = true
	structs.GlobalConfig.NoGolangPoc = false
	configurePocSources()
	if _, err := structs.GlobalEmbedPocs.ReadFile("config/pocs/3cx-management-console.yaml"); err == nil {
		t.Fatal("found embedded poc in external-only mode")
	}
	if !structs.GlobalConfig.NoGolangPoc {
		t.Fatal("built-in GoPoc is enabled in external-only mode")
	}
}
