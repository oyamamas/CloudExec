package cmd

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oyamamas/CloudExec/internal/utils"
	"github.com/spf13/cobra"
)

type exporterTestTransport func(*http.Request) (*http.Response, error)

func (f exporterTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func exporterTestResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

func TestExporterDebugEndpoints(t *testing.T) {
	for _, tt := range []struct {
		name       string
		vars       string
		varsStatus int
		cmdline    string
		wantSecret string
		wantVars   bool
	}{
		{"vars argv", `{"cmdline":["exporter","--password=example"]}`, 200, "exporter", "--password=example", true},
		{"pprof fallback", `not found`, 404, "exporter\x00--password\x00example", "--password example", false},
		{"vars outside cmdline", `{"db":"postgres://demo:example@localhost/db"}`, 200, "exporter", "postgres://demo:example@localhost/db", true},
		{"malformed vars", `<html>not JSON</html>`, 200, "exporter", "", false},
		{"unauthorized vars", `{"cmdline":["--password=example"]}`, 401, "exporter", "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var paths []string
			var reports []string
			s := exporterScanner{
				client: &http.Client{Transport: exporterTestTransport(func(r *http.Request) (*http.Response, error) {
					paths = append(paths, r.URL.Path)
					switch r.URL.Path {
					case "":
						return exporterTestResponse(200, "<h1>Node Exporter</h1>"), nil
					case "/debug/vars":
						return exporterTestResponse(tt.varsStatus, tt.vars), nil
					case "/debug/pprof/cmdline":
						return exporterTestResponse(200, tt.cmdline), nil
					case "/debug/pprof/":
						return exporterTestResponse(200, "<title>/debug/pprof/</title>"), nil
					default:
						t.Fatalf("unexpected URL %s", r.URL)
						return nil, errors.New("unexpected URL")
					}
				})},
				report: func(_ utils.Color, message string) { reports = append(reports, message) },
			}
			s.checkPort(context.Background(), "http://example.test:9100")
			if len(paths) != 4 {
				t.Fatalf("requested %v; all debug endpoints must be checked", paths)
			}
			output := strings.Join(reports, "\n")
			if got := strings.Contains(output, "/debug/vars - found"); got != tt.wantVars {
				t.Errorf("vars found = %v, want %v: %s", got, tt.wantVars, output)
			}
			if tt.wantSecret != "" && !strings.Contains(output, "secret: "+tt.wantSecret) {
				t.Errorf("missing secret %q in %s", tt.wantSecret, output)
			}
			if tt.wantSecret == "" && strings.Contains(output, "secret:") {
				t.Errorf("unexpected secret: %s", output)
			}
		})
	}
}

func TestExporterGlobalConcurrencyAndFailureRecovery(t *testing.T) {
	var active, peak, roots atomic.Int32
	var mu sync.Mutex
	seen := make(map[string]bool)
	s := exporterScanner{
		client: &http.Client{Transport: exporterTestTransport(func(r *http.Request) (*http.Response, error) {
			n := active.Add(1)
			defer active.Add(-1)
			for old := peak.Load(); n > old; old = peak.Load() {
				if peak.CompareAndSwap(old, n) {
					break
				}
			}
			time.Sleep(time.Millisecond)
			mu.Lock()
			seen[r.URL.String()] = true
			mu.Unlock()
			if r.URL.Path == "" {
				roots.Add(1)
				return exporterTestResponse(200, "<h1>Redis Exporter</h1>"), nil
			}
			if r.URL.Path == "/debug/vars" {
				return nil, errors.New("connection reset")
			}
			return exporterTestResponse(404, "missing"), nil
		})},
		report: func(utils.Color, string) {},
	}
	if err := s.scan(context.Background(), []string{"one.test", "two.test", "three.test", " ", " ::1 "}, 3, 9100, 9104); err != nil {
		t.Fatal(err)
	}
	if peak.Load() > 3 || peak.Load() < 2 {
		t.Fatalf("maximum concurrent requests = %d, want 2..3", peak.Load())
	}
	if roots.Load() != 20 || len(seen) != 80 {
		t.Fatalf("scan lost jobs after request failures: roots=%d, URLs=%d", roots.Load(), len(seen))
	}
	if !seen["http://[::1]:9100/debug/pprof/"] {
		t.Fatal("IPv6 address was not formatted correctly")
	}
}

func TestExporterTimeoutContinuesToNextEndpoint(t *testing.T) {
	var cmdlineCalled atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			io.WriteString(w, "<h1>Node Exporter</h1>")
		case "/debug/vars":
			<-r.Context().Done()
		case "/debug/pprof/cmdline":
			cmdlineCalled.Store(true)
			io.WriteString(w, "exporter\x00--password=example")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	s := exporterScanner{client: &http.Client{Timeout: 100 * time.Millisecond}, report: func(utils.Color, string) {}}
	s.checkPort(context.Background(), server.URL)
	if !cmdlineCalled.Load() {
		t.Fatal("timeout in vars prevented checking cmdline")
	}
}

func TestExporterScanCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	s := exporterScanner{
		client: &http.Client{Transport: exporterTestTransport(func(r *http.Request) (*http.Response, error) {
			close(started)
			<-r.Context().Done()
			return nil, r.Context().Err()
		})},
		report: func(utils.Color, string) {},
	}
	done := make(chan error, 1)
	go func() { done <- s.scan(ctx, []string{"example.test"}, 1, 9100, 9999) }()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("scan error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled scan did not stop its workers")
	}
}

type exporterTestBody struct {
	io.Reader
	closed bool
}

func (b *exporterTestBody) Close() error { b.closed = true; return nil }

type exporterErrorReader struct{}

func (exporterErrorReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestExporterFetchClosesBodies(t *testing.T) {
	for _, tt := range []struct {
		name    string
		status  int
		reader  io.Reader
		wantErr bool
	}{
		{"success", 200, strings.NewReader("ok"), false},
		{"HTTP error", 500, strings.NewReader("error"), false},
		{"read error", 200, exporterErrorReader{}, true},
		{"oversized", 200, strings.NewReader(strings.Repeat("x", maxExporterBodySize+1)), true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := &exporterTestBody{Reader: tt.reader}
			s := exporterScanner{client: &http.Client{Transport: exporterTestTransport(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tt.status, Body: body, Header: make(http.Header)}, nil
			})}}
			_, _, err := s.fetch(context.Background(), "http://example.test")
			if (err != nil) != tt.wantErr || !body.closed {
				t.Fatalf("fetch error=%v, body closed=%v", err, body.closed)
			}
		})
	}
}

func TestExportersOptions(t *testing.T) {
	for _, tt := range []struct{ threads, timeout string }{
		{"0", "2"}, {"-1", "2"}, {"bad", "2"}, {"1", "0"}, {"1", "-2"}, {"1", "bad"}, {"1", "999999999999999999999999"},
	} {
		if _, _, err := exportersOptions(map[string]string{"threads": tt.threads, "timeout": tt.timeout}); err == nil {
			t.Errorf("accepted invalid options: %+v", tt)
		}
	}
	threads, timeout, err := exportersOptions(map[string]string{"threads": "3", "timeout": "5"})
	if err != nil || threads != 3 || timeout != 5*time.Second {
		t.Fatalf("options = %d, %s, %v", threads, timeout, err)
	}
}

func TestExporterRelayRecognizesExporterTitle(t *testing.T) {
	var requested string
	s := exporterScanner{
		client: &http.Client{Transport: exporterTestTransport(func(r *http.Request) (*http.Response, error) {
			requested = r.URL.RequestURI()
			return exporterTestResponse(400, "target is required"), nil
		})},
		report: func(utils.Color, string) {},
	}
	s.checkRelay(context.Background(), "http://example.test:9187", "Prometheus PostgreSQL Exporter")
	if requested != "/probe?target=" {
		t.Fatalf("relay request = %q", requested)
	}
}

// More targets than workers and no detected exporters reproduced the merge
// regression: neither the WaitGroup nor the semaphore was released on return.
func TestExportersCommandCompletesWithNoExporters(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	host, portString, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		t.Fatal(err)
	}
	first, last := ExportersPortBegin, ExportersPortEnd
	ExportersPortBegin, ExportersPortEnd = port, port
	defer func() { ExportersPortBegin, ExportersPortEnd = first, last }()
	targetFile := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(targetFile, []byte(strings.Repeat(host+"\n", 3)), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := &cobra.Command{}
	cmd.Flags().Int("threads", 1, "")
	cmd.Flags().String("timeout", "1", "")
	cmd.Flags().String("inputlist", targetFile, "")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd.SetContext(ctx)
	done := make(chan error, 1)
	go func() { done <- runExporters(cmd, nil) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("exporters command deadlocked after workers returned without findings")
	}
}
