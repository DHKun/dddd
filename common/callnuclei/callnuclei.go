package callnuclei

import (
	"context"
	"embed"
	"os/signal"

	"dddd/common/nucleiadapter"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

type NucleiParams struct {
	TargetAndPocsName map[string][]string
	Proxy             string
	CallBack          func(result output.ResultEvent)
	NameForSearch     string
	NoInteractsh      bool
	Fs                embed.FS
	NP                string
	ExcludeTags       []string
	Severities        []string
	InteractshServer  string
	InteractshToken   string
}

func CallNuclei(param NucleiParams) []output.ResultEvent {
	ctx, stop := signal.NotifyContext(context.Background(), interruptSignals()...)
	defer stop()

	results, err := nucleiadapter.Scan(ctx, nucleiadapter.Config{
		TargetTemplates:  param.TargetAndPocsName,
		TemplatePath:     param.NP,
		Embedded:         param.Fs,
		Proxy:            param.Proxy,
		Callback:         param.CallBack,
		Search:           param.NameForSearch,
		NoInteractsh:     param.NoInteractsh,
		ExcludeTags:      param.ExcludeTags,
		Severities:       param.Severities,
		InteractshServer: param.InteractshServer,
		InteractshToken:  param.InteractshToken,
		Audit:            gologger.Audit,
	})
	if err != nil {
		gologger.Error().Msgf("Could not run nuclei: %s\n", err)
	}
	return results
}
