package mysql

import (
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"
)

func TestNormalizeNucleiMySQLDSN(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		dsn         string
		wantNetwork string
	}{
		{
			name:        "tcp uses isolated network",
			dsn:         "user:password@tcp(127.0.0.1:3306)/mysql",
			wantNetwork: nucleiMySQLNetwork,
		},
		{
			name:        "unix socket remains unchanged",
			dsn:         "user:password@unix(/tmp/mysql.sock)/mysql",
			wantNetwork: "unix",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			normalized, err := normalizeNucleiMySQLDSN(test.dsn)
			if err != nil {
				t.Fatalf("normalizeNucleiMySQLDSN(): %v", err)
			}
			config, err := mysqldriver.ParseDSN(normalized)
			if err != nil {
				t.Fatalf("ParseDSN(): %v", err)
			}
			if config.Net != test.wantNetwork {
				t.Fatalf("network = %q, want %q", config.Net, test.wantNetwork)
			}
		})
	}
}
