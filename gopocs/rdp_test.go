package gopocs

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tomatome/grdp/emission"
	"github.com/tomatome/grdp/glog"
)

func TestRDPLoginStateRecoversEmitterPanic(t *testing.T) {
	t.Parallel()

	state := newRDPLoginState()
	emitter := emission.NewEmitter()
	emitter.RecoverWith(state.recoverProtocolPanic)
	emitter.On("challenge", func() {
		panic("missing NLA token")
	})

	emitter.Emit("challenge")

	select {
	case err := <-state.done:
		if err == nil {
			t.Fatal("recovered protocol panic returned a nil error")
		}
		if !strings.Contains(err.Error(), "missing NLA token") {
			t.Fatalf("recovered error = %q, want panic details", err)
		}
	case <-time.After(time.Second):
		t.Fatal("protocol panic did not complete the login state")
	}
}

func TestRDPLoginStateCompletesOnce(t *testing.T) {
	t.Parallel()

	state := newRDPLoginState()
	state.finish(nil)
	state.finish(errors.New("late error"))

	if err := <-state.done; err != nil {
		t.Fatalf("first completion error = %v, want nil", err)
	}

	select {
	case err := <-state.done:
		t.Fatalf("received duplicate completion: %v", err)
	default:
	}
}

func TestRDPLoginHonorsTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)

		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(io.Discard, conn)
	}()

	client := NewClient(listener.Addr().String(), glog.NONE)
	started := time.Now()
	err = client.Login("", "user", "password", 1)
	elapsed := time.Since(started)

	if err == nil {
		t.Fatal("Login() returned nil for a server that never completed negotiation")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("Login() returned after %s, want at most 3s", elapsed)
	}

	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("test server did not observe the client connection closing")
	}
}
