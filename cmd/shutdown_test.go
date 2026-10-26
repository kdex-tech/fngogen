package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerate_CustomServerScaffolded is kdex-tech/fngogen#12: every function
// gets a never-overwritten custom_server.go whose ServerConfig hook main.go
// calls on the *http.Server before it listens.
func TestGenerate_CustomServerScaffolded(t *testing.T) {
	generateFixture(t, "t21", "../../test-fixtures/openapi-spec.json")

	customServer, err := os.ReadFile("cmd/custom_server.go")
	require.NoError(t, err)
	assert.Contains(t, string(customServer), "func ServerConfig(srv *http.Server)")

	mainSrc, err := os.ReadFile("cmd/main.go")
	require.NoError(t, err)
	assert.Contains(t, string(mainSrc), "ServerConfig(server)")

	if out, err := exec.Command("go", "build", "./...").CombinedOutput(); !assert.NoError(t, err, string(out)) {
		return
	}
}

func TestGenerate_CustomServerNotOverwritten(t *testing.T) {
	generateFixture(t, "t22", "../../test-fixtures/openapi-spec.json")

	const edited = "package main\n\nimport \"net/http\"\n\n// edited by the function author\nfunc ServerConfig(srv *http.Server) {}\n"
	require.NoError(t, os.WriteFile("cmd/custom_server.go", []byte(edited), 0644))
	require.NoError(t, run([]string{"--spec", "openapi-spec.json"}))

	got, err := os.ReadFile("cmd/custom_server.go")
	require.NoError(t, err)
	assert.Equal(t, edited, string(got))
}

// shutdownHandlers replace the scaffolded custom.go / custom_raw.go of the
// openapi-spec-sse.json fixture with handlers that exercise shutdown: a slow
// ordinary request, a stream that honours ShuttingDown(), and a stream that
// ignores it.
const shutdownCustom = `package main

import (
	"context"
	"time"

	"function/api"
)

type slowHandler struct{}

func (slowHandler) GenV1StatusGet(ctx context.Context) (*api.Update, error) {
	time.Sleep(1500 * time.Millisecond)
	return &api.Update{Message: "done"}, nil
}

func NewHandler() api.Handler { return slowHandler{} }
`

const shutdownCustomRaw = `package main

import (
	"context"
	"fmt"
	"net/http"

	"function/api"
)

type streams struct{}

func NewRawHandler() api.RawHandler { return streams{} }

func open(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "data: open\n\n")
	_ = http.NewResponseController(w).Flush()
}

func (streams) GenV1EventsGet(ctx context.Context, w http.ResponseWriter) error {
	open(w)
	select {
	case <-ShuttingDown():
		fmt.Fprint(w, "data: bye\n\n")
	case <-ctx.Done():
	}
	return nil
}

func (streams) GenV1EventsRawGet(ctx context.Context, w http.ResponseWriter) error {
	open(w)
	<-ctx.Done()
	return nil
}
`

// TestGeneratedServer_GracefulShutdown drives a built function binary through
// SIGTERM (#12): in-flight requests drain and the process exits 0, the
// listener stops accepting, a stream that watches ShuttingDown() ends at once,
// and a stream that ignores it is cut off when the grace expires (exit 1).
func TestGeneratedServer_GracefulShutdown(t *testing.T) {
	generateFixture(t, "t23", "../../test-fixtures/openapi-spec-sse.json")
	require.NoError(t, os.WriteFile("cmd/custom.go", []byte(shutdownCustom), 0644))
	require.NoError(t, os.WriteFile("cmd/custom_raw.go", []byte(shutdownCustomRaw), 0644))
	bin := filepath.Join(t.TempDir(), "fn")
	if out, err := exec.Command("go", "build", "-o", bin, "./cmd/").CombinedOutput(); err != nil {
		t.Fatalf("build function: %v\n%s", err, out)
	}

	t.Run("in-flight request drains, listener closes, exit 0", func(t *testing.T) {
		fn, url := startFunction(t, bin)

		type result struct {
			status int
			body   string
			err    error
		}
		done := make(chan result, 1)
		go func() {
			resp, err := http.Get(url + "/v1/status")
			if err != nil {
				done <- result{err: err}
				return
			}
			defer func() { _ = resp.Body.Close() }()
			b, _ := io.ReadAll(resp.Body)
			done <- result{status: resp.StatusCode, body: string(b)}
		}()
		time.Sleep(300 * time.Millisecond)
		require.NoError(t, fn.Process.Signal(syscall.SIGTERM))

		time.Sleep(300 * time.Millisecond)
		_, err := net.DialTimeout("tcp", strings.TrimPrefix(url, "http://"), time.Second)
		assert.Error(t, err, "the listener must stop accepting once shutdown starts")

		r := <-done
		require.NoError(t, r.err)
		assert.Equal(t, http.StatusOK, r.status)
		assert.Contains(t, r.body, "done")
		assert.Equal(t, 0, waitExit(t, fn, 5*time.Second))
	})

	t.Run("stream watching ShuttingDown ends at once, exit 0", func(t *testing.T) {
		fn, url := startFunction(t, bin, "SHUTDOWN_GRACE_SECONDS=10")
		lines := openStream(t, url+"/v1/events")

		start := time.Now()
		require.NoError(t, fn.Process.Signal(syscall.SIGTERM))
		assert.Equal(t, "data: bye", nextLine(t, lines, 3*time.Second))
		assert.Equal(t, 0, waitExit(t, fn, 3*time.Second))
		assert.Less(t, time.Since(start), 3*time.Second, "the stream must not sit out the 10s grace")
	})

	t.Run("stream ignoring ShuttingDown is cut off at the grace, exit 1", func(t *testing.T) {
		fn, url := startFunction(t, bin, "SHUTDOWN_GRACE_SECONDS=1")
		lines := openStream(t, url+"/v1/events/raw")

		require.NoError(t, fn.Process.Signal(syscall.SIGTERM))
		assert.Equal(t, 1, waitExit(t, fn, 5*time.Second))
		_, open := <-lines
		assert.False(t, open, "the stream must end when the grace expires")
	})
}

func startFunction(t *testing.T, bin string, env ...string) (*exec.Cmd, string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())

	fn := exec.Command(bin)
	fn.Env = append(os.Environ(), append(env, fmt.Sprintf("PORT=%d", port))...)
	fn.Stdout, fn.Stderr = os.Stderr, os.Stderr
	require.NoError(t, fn.Start())
	t.Cleanup(func() { _ = fn.Process.Kill() })

	url := fmt.Sprintf("http://127.0.0.1:%d", port)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			_ = c.Close()
			return fn, url
		}
		if time.Now().After(deadline) {
			t.Fatal("function did not start listening")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// openStream opens an SSE stream, waits for its first event, and returns a
// channel of the remaining non-empty lines, closed when the stream ends.
func openStream(t *testing.T, url string) <-chan string {
	t.Helper()
	resp, err := http.Get(url)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	lines := make(chan string, 16)
	go func() {
		defer close(lines)
		defer func() { _ = resp.Body.Close() }()
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if sc.Text() != "" {
				lines <- sc.Text()
			}
		}
	}()
	require.Equal(t, "data: open", nextLine(t, lines, 3*time.Second))
	return lines
}

func nextLine(t *testing.T, lines <-chan string, timeout time.Duration) string {
	t.Helper()
	select {
	case l, ok := <-lines:
		if !ok {
			t.Fatal("stream ended")
		}
		return l
	case <-time.After(timeout):
		t.Fatal("timed out waiting for a stream line")
	}
	return ""
}

func waitExit(t *testing.T, fn *exec.Cmd, timeout time.Duration) int {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn.Wait() }()
	select {
	case err := <-done:
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode()
		}
		require.NoError(t, err)
		return 0
	case <-time.After(timeout):
		t.Fatal("function did not exit")
	}
	return -1
}
