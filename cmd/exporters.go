/*
Copyright © 2026 oyama forked cotsom
*/
package cmd

import (
	"fmt"
	"os"
	"strconv"
	"sync"

	"github.com/cotsom/CloudExec/internal/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	RelayFlag bool   = false
	RelayIP   string = ""
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
			go checkKube(target, &wg, sem, flags)
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
	exportersCmd.Flags().StringVarP(&RelayIP, "relay-ip", "-R", "", "Relay IP")
}

func checkExportersDebugEndpoints(target string, wg *sync.WaitGroup, sem chan struct{}, flags map[string]string) {
}
func checkExportersRelay(target string, wg *sync.WaitGroup, sem chan struct{}, flags map[string]string) {
}
