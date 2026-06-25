package nuclei

import (
	"context"
	"errors"
	"io/fs"
	"sort"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	"github.com/projectdiscovery/nuclei/v3/pkg/loader/workflow"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	errorutil "github.com/projectdiscovery/utils/errors"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

// DDDDScanOptions describes dddd's target-to-template workflow mapping.
type DDDDScanOptions struct {
	TargetTemplates   map[string][]string
	EmbeddedTemplates fs.FS
	Search            string
	ExcludeTags       []string
	Severities        []string
}

// ExecuteDDDDWithCtx executes only the templates selected for each target.
// External templates are resolved before embedded templates, which preserves
// dddd's external override behavior for duplicate filenames.
func (e *NucleiEngine) ExecuteDDDDWithCtx(ctx context.Context, options DDDDScanOptions, callback func(event *output.ResultEvent)) error {
	if len(options.TargetTemplates) == 0 {
		return ErrNoTargetsAvailable
	}

	workflowLoader, err := workflow.NewLoader(&e.executerOpts)
	if err != nil {
		return errorutil.New("Could not create workflow loader: %s\n", err)
	}
	e.executerOpts.WorkflowLoader = workflowLoader

	store, err := loader.New(loader.NewConfig(e.opts, e.catalog, e.executerOpts))
	if err != nil {
		return errorutil.New("Could not create loader client: %s\n", err)
	}

	templatePaths := e.externalTemplatePaths()
	embeddedPaths, err := embeddedTemplatePaths(options.EmbeddedTemplates)
	if err != nil {
		return err
	}
	templatePaths = append(templatePaths, embeddedPaths...)

	if callback != nil {
		e.resultCallbacks = append(e.resultCallbacks, callback)
	}

	groups := groupTargetsByTemplates(options.TargetTemplates, options.Search)
	executed := false
	for _, group := range groups {
		selected := store.LoadTemplatesWithNames(
			options.EmbeddedTemplates,
			templatePaths,
			group.templates,
			options.ExcludeTags,
			options.Severities,
			options.Search != "",
		)
		if len(selected) == 0 {
			continue
		}
		executed = true
		e.engine.ExecuteScanWithOpts(ctx, selected, provider.NewSimpleInputProviderWithUrls(group.targets...), e.opts.DisableClustering)
		e.engine.WorkPool().Wait()
	}
	if !executed {
		return ErrNoTemplatesAvailable
	}
	return nil
}

func (e *NucleiEngine) externalTemplatePaths() []string {
	var result []string
	for _, source := range e.opts.Templates {
		paths, err := e.catalog.GetTemplatePath(source)
		if err == nil {
			result = append(result, paths...)
		}
	}
	return sliceutil.Dedupe(result)
}

func embeddedTemplatePaths(embedded fs.FS) ([]string, error) {
	if embedded == nil {
		return nil, nil
	}
	var result []string
	err := fs.WalkDir(embedded, ".", func(templatePath string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		lowerPath := strings.ToLower(templatePath)
		if !entry.IsDir() && (strings.HasSuffix(lowerPath, ".yaml") || strings.HasSuffix(lowerPath, ".yml")) {
			result = append(result, templatePath)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	sort.Strings(result)
	return result, nil
}

type ddddTargetGroup struct {
	templates []string
	targets   []string
}

func groupTargetsByTemplates(targetTemplates map[string][]string, search string) []ddddTargetGroup {
	groups := make(map[string]*ddddTargetGroup)
	for target, templateNames := range targetTemplates {
		if search != "" {
			templateNames = []string{search}
		}
		templateNames = sliceutil.Dedupe(templateNames)
		sorted := append([]string(nil), templateNames...)
		sort.Strings(sorted)
		key := strings.Join(sorted, "\x00")
		group := groups[key]
		if group == nil {
			group = &ddddTargetGroup{templates: sorted}
			groups[key] = group
		}
		group.targets = append(group.targets, target)
	}

	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]ddddTargetGroup, 0, len(keys))
	for _, key := range keys {
		group := groups[key]
		sort.Strings(group.targets)
		result = append(result, *group)
	}
	return result
}
