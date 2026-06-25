package protocolstate

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

func TestInitDoesNotOverrideApplicationMySQLTCPDialer(t *testing.T) {
	sentinelErr := errors.New("application mysql tcp dialer")
	var applicationDialerCalled atomic.Bool

	mysql.RegisterDialContext("tcp", func(context.Context, string) (net.Conn, error) {
		applicationDialerCalled.Store(true)
		return nil, sentinelErr
	})
	t.Cleanup(func() {
		mysql.RegisterDialContext("tcp", func(ctx context.Context, addr string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "tcp", addr)
		})
	})

	Dialer = nil
	if err := Init(&types.Options{}); err != nil {
		t.Fatalf("Init(): %v", err)
	}
	Close()
	Dialer = nil

	db, err := sql.Open("mysql", "user:password@tcp(127.0.0.1:3306)/?timeout=100ms")
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = db.PingContext(ctx)

	if !applicationDialerCalled.Load() {
		t.Fatal("Nuclei replaced the application MySQL tcp dialer")
	}
	if !errors.Is(err, sentinelErr) {
		t.Fatalf("PingContext() error = %v, want %v", err, sentinelErr)
	}
}
