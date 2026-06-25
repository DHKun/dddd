package automaticscan

import (
	"embed"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeAppName(t *testing.T) {
	appName := normalizeAppName("JBoss")
	require.Equal(t, "jboss", appName, "could not get normalized name")

	appName = normalizeAppName("JBoss:2.3.5")
	require.Equal(t, "jboss", appName, "could not get normalized name")
}

func TestGetTemplatePathByEmptyFS(t *testing.T) {
	paths, err := getTemplatePathByFS(embed.FS{})
	require.NoError(t, err)
	require.Empty(t, paths)
}
