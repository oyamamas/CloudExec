/*
forked cotsom/CloudExec
Copyright 2026 oyama
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cotsom/CloudExec/internal/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	DebugEndpoints = []string{"/debug/vars", "/debug/pprof/cmdline"}
	RelayEndpoints = []string{"/probe?target=", "/scrape?target="}
)

func init() {
	exportersCmd.Flags().IntP("threads", "t", 100, "threads")
	exportersCmd.Flags().StringP("inputlist", "i", "", "Input from list of hosts")
	exportersCmd.Flags().StringP("relay", "r", "", "IP to relay to")
	rootCmd.AddCommand(exportersCmd)

}

// exportersCmd represents the exporters command
var exportersCmd = &cobra.Command{
	Use:   "exporters",
	Short: "Check Exporters for common misconfigs",
	Long: `Check Exporters for common misconfigs:
			- /debug/pprof/cmdline
			- /debug/vars
			- relay ability`,
	Run: func(cmd *cobra.Command, args []string) {

		flags := make(map[string]string)
		cmd.Flags().VisitAll(func(f *pflag.Flag) {
			flags[f.Name] = f.Value.String()
		})

		targets, err := utils.GetTargets(flags, args)
		if err != nil {
			utils.Colorize(utils.ColorRed, err.Error())
			return
		}

		// main logic goes here
		var wg sync.WaitGroup
		var sem chan struct{}

		//set threads
		threads, err := strconv.Atoi(flags["threads"])
		if err != nil {
			fmt.Println("You have to set correct number of threads")
			os.Exit(0)
		}
		sem = make(chan struct{}, threads)

		progress := 0
		for i, target := range targets {
			wg.Add(1)
			sem <- struct{}{}
			go checkExporters(target, &wg, sem, flags)
			utils.ProgressBar(len(targets), i+1, &progress)
		}
		fmt.Println("")
		wg.Wait()

	},
}

func checkExporters(target string, wg *sync.WaitGroup, sem chan struct{}, flags map[string]string) {

	client := http.Client{
		Timeout: 1 * time.Second,
	}

	for _, endpoint := range DebugEndpoints {
		url := fmt.Sprintf("http://%s%s", target, endpoint)
		response, err := utils.HttpRequest(url, http.MethodGet, []byte(""), client)
		if err != nil {
			continue
		}

		defer response.Body.Close()

		if response.StatusCode != http.StatusOK {
			utils.Colorize(utils.ColorYellow, fmt.Sprintf("[-] %s - endpoint %s not accesible", target, endpoint))
		}

		respBody, err := io.ReadAll(response.Body)

		if strings.Contains(string(respBody), "cmdline") {
			var data map[string]interface{}
			if err := json.Unmarshal(respBody, &data); err != nil {
				continue
			}

			if cmdline, ok := data["cmdline"]; ok && cmdline != nil {
				cmdlineData := fmt.Sprintf("%v", cmdline)
				utils.Colorize(utils.ColorGreen, fmt.Sprintf("[+] %s - cmdline found\n %s \n", target, cmdlineData))
			}
		} else {
			utils.Colorize(utils.ColorRed, fmt.Sprintf("[-] %s - cmdline not found", endpoint))
		}

	}

}
