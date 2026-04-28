/*
Copyright © 2026 oyama forked cotsom
*/
package cmd

import (
	"fmt"
	"io/ioutil"
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
	RelayFlag          bool   = false
	RelayIP            string = ""
	ExportersPortBegin        = 9100
	ExportersPortEnd          = 9999
)
var DebugEndpoints = []string{"/debug/vars",
	"/debug/pprof/cmdline",
	"/debug/pprof",
}

var RelayEndpoints = []string{
	"/probe?target=",
	"/scrape?target="}

var exportersCmd = &cobra.Command{
	Use:   "exporters",
	Short: "Prometheus exporters Weaknesses",
	Long: `General Exporters Weaknesses:
			- /debug/pprof/
			- /debug/pprof/cmdline/
			- /debug/vars
			- relay attacks`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("exporters called")
		flags := make(map[string]string)
		cmd.Flags().VisitAll(func(f *pflag.Flag) {
			flags[f.Name] = f.Value.String()
		})

		targets, err := utils.GetTargets(flags, args)
		if err != nil {
			utils.Colorize(utils.ColorRed, err.Error())
			return
		}

		//MAIN LOGIC
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

func init() {
	rootCmd.AddCommand(exportersCmd)
	exportersCmd.Flags().IntP("threads", "t", 100, "threads")
	exportersCmd.Flags().StringP("inputlist", "i", "", "Input from list of hosts")
	exportersCmd.Flags().StringP("module", "M", "", "Choose module")
	exportersCmd.Flags().StringP("timeout", "", "", "Count of seconds for waiting http response")
	exportersCmd.Flags().BoolVarP(&RelayFlag, "relay", "r", false, "Enable relay attack")
	exportersCmd.Flags().StringVarP(&RelayIP, "relay-ip", "R", "", "Relay IP")
}

func checkExporters(target string, wg *sync.WaitGroup, sem chan struct{}, flags map[string]string) {
	defer func() {
		<-sem
		wg.Done()
	}()

	ports := detectExportersPort(target)
	fmt.Println(ports)
	client := http.Client{
		Timeout: 1 * time.Second,
	}
	for _, port := range ports {
		for _, endpoint := range DebugEndpoints {
			url := fmt.Sprintf("http://%s:%d%s", target, port, endpoint)
			response, err := utils.HttpRequest(url, http.MethodGet, []byte(""), client)

			if err != nil {
				// fmt.Println(err)
				continue
			}

			defer response.Body.Close()

			respBody, err := ioutil.ReadAll(response.Body)
			if err != nil {
				fmt.Printf("client: could not read response body: %s\n", err)
			}

			if strings.Contains(string(respBody), "cmdline") {
				utils.Colorize(utils.ColorBlue, fmt.Sprintf("[*] %s:%s:%s - found", target, port, endpoint))
			}
		}
	}

}

func checkExportersRelay(target string, wg *sync.WaitGroup, sem chan struct{}, flags map[string]string) {
}

func detectExportersPort(target string) []int {
	ports := []int{}

	client := http.Client{
		Timeout: 1 * time.Second,
	}

	//Check Ports
	for port := ExportersPortBegin; port <= ExportersPortEnd; port++ {
		url := fmt.Sprintf("http://%s:%s", target, strconv.Itoa(port))
		response, err := utils.HttpRequest(url, http.MethodGet, []byte(""), client)
		if err != nil {
			// fmt.Println(err)
			continue
		}

		if response.StatusCode == 200 {
			exporterType, err := utils.ParseExportersType(response.Body)
			if err != nil {
				continue
			}
			utils.Colorize(utils.ColorBlue, fmt.Sprintf("[*] %s - detected %s on %s port", target, exporterType,
				strconv.Itoa(port)))
			ports = append(ports, port)

		} else {
			continue
		}

		defer response.Body.Close()
	}
	return ports
}
