/*
Copyright © 2026 oyama forked cotsom
*/
package cmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oyamamas/CloudExec/internal/secretsengine"
	"github.com/oyamamas/CloudExec/internal/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	RelayFlag          = false
	RelayIP            = ""
	ExportersPortBegin = 9100
	ExportersPortEnd   = 9999
)

var RelayEndpoints = map[string]string{
	"postgres":      "/probe?target=",
	"pgbouncer":     "/probe?target=",
	"proxmox":       "/pve?target=",
	"redis":         "/scrape?target=",
	"elasticsearch": "/probe?target=",
}

var DebugEndpoints = []string{
	"/debug/vars",
	"/debug/pprof/cmdline",
	"/debug/pprof/",
}

const maxExporterBodySize = 4 << 20

var exportersCmd = &cobra.Command{
	Use:   "exporters",
	Short: "Prometheus exporters Weaknesses",
	Long: `General Exporters Weaknesses:
			- /debug/pprof/
			- /debug/pprof/cmdline
			- /debug/vars
			- relay attacks`,
	RunE: runExporters,
}

func runExporters(cmd *cobra.Command, args []string) error {
	flags := make(map[string]string)
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		flags[f.Name] = f.Value.String()
	})
	threads, timeout, err := exportersOptions(flags)
	if err != nil {
		return err
	}
	targets, err := utils.GetTargets(flags, args)
	if err != nil {
		return err
	}
	if err := secretsengine.LoadRules(); err != nil {
		return err
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Preserve the existing support for exporters redirecting to self-signed HTTPS.
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	// The scan touches many different hosts and ports. Bound the idle pool too.
	transport.MaxIdleConns = threads
	defer transport.CloseIdleConnections()
	scanner := exporterScanner{
		client: &http.Client{Timeout: timeout, Transport: transport},
		relay:  RelayFlag,
		report: utils.Colorize,
	}
	return scanner.scan(cmd.Context(), targets, threads, ExportersPortBegin, ExportersPortEnd)
}

func exportersOptions(flags map[string]string) (int, time.Duration, error) {
	threads, err := strconv.Atoi(flags["threads"])
	if err != nil || threads <= 0 {
		return 0, 0, fmt.Errorf("threads must be a positive integer")
	}
	timeoutValue := flags["timeout"]
	if timeoutValue == "" {
		timeoutValue = "2"
	}
	timeout, err := time.ParseDuration(timeoutValue + "s")
	if err != nil || timeout <= 0 {
		return 0, 0, fmt.Errorf("timeout must be a positive number of seconds")
	}
	return threads, timeout, nil
}

func init() {
	rootCmd.AddCommand(exportersCmd)
	exportersCmd.Flags().IntP("threads", "t", 100, "Maximum concurrent exporter checks across all hosts and ports")
	exportersCmd.Flags().StringP("inputlist", "i", "", "Input from list of hosts")
	exportersCmd.Flags().StringP("module", "M", "", "Choose module")
	exportersCmd.Flags().StringP("timeout", "", "2", "Seconds to wait for each HTTP response")
	exportersCmd.Flags().BoolVarP(&RelayFlag, "relay", "r", false, "Enable relay attack")
}

type exporterScanner struct {
	client *http.Client
	relay  bool
	report func(utils.Color, string)
}

func (s *exporterScanner) scan(ctx context.Context, targets []string, threads, firstPort, lastPort int) error {
	if threads <= 0 {
		return fmt.Errorf("threads must be a positive integer")
	}
	if firstPort < 1 || lastPort > 65535 || firstPort > lastPort {
		return fmt.Errorf("invalid exporter port range")
	}
	// A single pool bounds both detection and debug requests. Nested per-host
	// pools previously multiplied the requested concurrency by itself.
	jobs := make(chan string)
	var wg sync.WaitGroup
	for range threads {
		wg.Go(func() {
			for baseURL := range jobs {
				if ctx.Err() != nil {
					return
				}
				s.checkPort(ctx, baseURL)
			}
		})
	}
produce:
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		for port := firstPort; port <= lastPort; port++ {
			baseURL := "http://" + net.JoinHostPort(target, strconv.Itoa(port))
			select {
			case jobs <- baseURL:
			case <-ctx.Done():
				break produce
			}
		}
	}
	close(jobs)
	wg.Wait()
	return ctx.Err()
}

// Read and close each response before starting another request, including on
// status/read errors. The size limit prevents a single page exhausting memory.
func (s *exporterScanner) fetch(ctx context.Context, url string) ([]byte, int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	response, err := s.client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxExporterBodySize+1))
	if err != nil {
		return nil, response.StatusCode, err
	}
	if len(body) > maxExporterBodySize {
		return nil, response.StatusCode, fmt.Errorf("response exceeds %d bytes", maxExporterBodySize)
	}
	return body, response.StatusCode, nil
}

func (s *exporterScanner) checkPort(ctx context.Context, baseURL string) {
	body, status, err := s.fetch(ctx, baseURL)
	if err != nil || status != http.StatusOK {
		return
	}
	exporterType, err := utils.ParseExportersType(bytes.NewReader(body))
	if err != nil {
		return
	}
	s.report(utils.ColorBlue, fmt.Sprintf("[*] %s - detected %s", baseURL, exporterType))

	for _, endpoint := range DebugEndpoints {
		url := baseURL + endpoint
		body, status, err := s.fetch(ctx, url)
		if err != nil {
			if ctx.Err() == nil {
				s.report(utils.ColorYellow, fmt.Sprintf("[*] %s - request failed: %v", url, err))
			}
			continue
		}
		if status != http.StatusOK || len(bytes.TrimSpace(body)) == 0 {
			continue
		}
		text := strings.ReplaceAll(string(body), "\x00", " ")
		if endpoint == "/debug/vars" {
			data, err := utils.UnmarshallJsonString(text)
			if err != nil {
				continue
			}
			// Decode JSON escaping and join argv for rules spanning arguments.
			// Also scan the whole document: expvars can expose other secrets.
			if cmdline, ok := utils.ExportersExtractCmdline(data); ok {
				text = cmdline + "\n" + text
			}
		}
		s.report(utils.ColorGreen, fmt.Sprintf("[*] %s - found", url))
		if secret := secretsengine.FindSecrets(text); secret != "" {
			s.report(utils.ColorRed, fmt.Sprintf("[*] %s - secret: %s", url, secret))
		}
	}
	if s.relay && ctx.Err() == nil {
		s.checkRelay(ctx, baseURL, exporterType)
	}
}

func (s *exporterScanner) checkRelay(ctx context.Context, baseURL, exporterType string) {
	name := strings.ToLower(exporterType)
	name = strings.NewReplacer("_", " ", "-", " ").Replace(name)
	name = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(name, "prometheus "), "exporter"))
	if name == "postgresql" {
		name = "postgres"
	}
	endpoint, ok := RelayEndpoints[name]
	if !ok {
		return
	}
	body, _, err := s.fetch(ctx, baseURL+endpoint)
	if err == nil && len(body) > 0 {
		s.report(utils.ColorYellow, fmt.Sprintf("[*] %s%s - potential relay", baseURL, endpoint))
	}
}
