package nucleiadapter

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// Config contains the dddd-owned scan configuration passed to the Nuclei SDK.
type Config struct {
	TargetTemplates  map[string][]string
	TemplatePath     string
	Embedded         fs.FS
	Proxy            string
	Callback         func(output.ResultEvent)
	Search           string
	NoInteractsh     bool
	ExcludeTags      []string
	Severities       []string
	InteractshServer string
	InteractshToken  string
	Audit            bool
}

// Scan runs dddd's workflow-selected templates through the public Nuclei SDK.
func Scan(ctx context.Context, config Config) ([]output.ResultEvent, error) {
	templatePath, err := filepath.Abs(config.TemplatePath)
	if err != nil {
		return nil, err
	}

	interactOptions := interactsh.DefaultOptions(nil, nil, nil)
	if config.InteractshServer != "" {
		interactOptions.ServerURL = config.InteractshServer
	}
	interactOptions.Authorization = config.InteractshToken
	interactOptions.NoInteractsh = config.NoInteractsh
	interactOptions.Debug = config.Audit
	interactOptions.DebugRequest = config.Audit
	interactOptions.DebugResponse = config.Audit

	sdkOptions := []nuclei.NucleiSDKOptions{
		nuclei.DisableUpdateCheck(),
		nuclei.DisableDefaultIgnore(),
		nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{Templates: []string{templatePath}}),
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{ExcludeTags: config.ExcludeTags}),
		nuclei.WithGlobalRateLimitCtx(ctx, 150, time.Second),
		nuclei.WithInteractshOptions(nuclei.InteractshOpts(*interactOptions)),
		nuclei.WithVerbosity(nuclei.VerbosityOptions{
			Debug:         config.Audit,
			DebugRequest:  config.Audit,
			DebugResponse: config.Audit,
		}),
		nuclei.WithOptions(configureOptions),
	}
	if config.Proxy != "" {
		sdkOptions = append(sdkOptions, nuclei.WithProxy([]string{config.Proxy}, false))
	}

	engine, err := nuclei.NewNucleiEngineCtx(ctx, sdkOptions...)
	if err != nil {
		return nil, err
	}
	defer engine.Close()

	var mutex sync.Mutex
	results := make([]output.ResultEvent, 0)
	callback := func(event *output.ResultEvent) {
		if event == nil {
			return
		}
		result := *event
		mutex.Lock()
		results = append(results, result)
		if config.Callback != nil {
			config.Callback(result)
		}
		mutex.Unlock()
	}

	err = engine.ExecuteDDDDWithCtx(ctx, nuclei.DDDDScanOptions{
		TargetTemplates:   config.TargetTemplates,
		EmbeddedTemplates: config.Embedded,
		Search:            config.Search,
		ExcludeTags:       config.ExcludeTags,
		Severities:        config.Severities,
	}, callback)
	if errors.Is(err, nuclei.ErrNoTemplatesAvailable) {
		gologger.Info().Msg("Nuclei引擎无结果，下次好运！")
		return results, nil
	}
	return results, err
}

func configureOptions(options *types.Options) {
	options.AutomaticScan = false
	options.NoStrictSyntax = false
	options.RemoteTemplateDomainList = []string{"templates.nuclei.sh"}
	options.OmitRawRequests = false
	options.NoMeta = false
	options.FollowRedirects = false
	options.FollowHostRedirects = false
	options.MaxRedirects = 10
	options.DisableRedirects = false
	options.ResponseReadSize = 10 * 1024 * 1024
	options.ResponseSaveSize = 1024 * 1024
	options.BulkSize = 25
	options.TemplateThreads = 25
	options.HeadlessBulkSize = 10
	options.HeadlessTemplateThreads = 10
	options.PayloadConcurrency = 25
	options.ProbeConcurrency = 50
	options.Timeout = 12
	options.Retries = 2
	options.MaxHostError = 50
	options.Project = false
	options.StopAtFirstMatch = false
	options.Stream = false
	options.ScanStrategy = "auto"
	options.InputReadTimeout = 3 * time.Minute
	options.DisableHTTPProbe = true
	options.DisableStdin = true
	options.Headless = false
	options.EnableCodeTemplates = false
	options.EnableCloudUpload = false
	options.PublicTemplateDisableDownload = true
}
