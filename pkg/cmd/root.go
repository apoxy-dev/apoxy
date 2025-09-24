package cmd

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"

	"github.com/apoxy-dev/apoxy/config"
	"github.com/apoxy-dev/apoxy/pkg/cmd/alpha"
	"github.com/apoxy-dev/apoxy/pkg/cmd/tunnel"
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "apoxy",
	Short: "Apoxy helps you expose, explore, and evolve your APIs and services.",
	Long: `The Apoxy CLI is the quickest and easiest way to create and control Apoxy proxies.

Start by creating an account on https://apoxy.dev and logging in with 'apoxy auth'.
`,
	DisableAutoGenTag: true,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if config.PprofEnabled {
			go func() {
				log.Println("Starting pprof server on :6060")
				if err := http.ListenAndServe(":6060", nil); err != nil {
					log.Printf("pprof server failed: %v", err)
				}
			}()
		}
	},
}

// ExecuteContext executes root command with context.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func ExecuteContext(ctx context.Context) error {
	return RootCmd.ExecuteContext(ctx)
}

func init() {
	RootCmd.PersistentFlags().StringVar(&config.ConfigFile, "config", "", "Config file (default is $HOME/.apoxy/config.yaml).")
	RootCmd.PersistentFlags().BoolVar(&config.AlsoLogToStderr, "alsologtostderr", false, "Log to standard error as well as files.")
	RootCmd.PersistentFlags().BoolVarP(&config.Verbose, "verbose", "v", false, "Enable verbose output.")
	RootCmd.PersistentFlags().BoolVar(&config.LocalMode, "local", false, "Run in local mode.")
	RootCmd.PersistentFlags().StringVar(&config.ProjectID, "project", "", "The project ID to use.")
	RootCmd.PersistentFlags().BoolVar(&config.PprofEnabled, "pprof", false, "Enable pprof HTTP server on :6060.")

	RootCmd.AddCommand(alpha.Cmd())
	RootCmd.AddCommand(tunnel.Cmd())
}

// GenerateDocs generates the docs in the docs folder.
func GenerateDocs() {
	anchorLinks := func(s string) string {
		s = strings.ReplaceAll(s, "_", "-")
		s = strings.ToLower(s)
		s = strings.ReplaceAll(s, ".md", "")
		return fmt.Sprintf("#%s", s)
	}
	emptyStr := func(s string) string { return "" }
	files, err := genMarkdownTreeCustom(RootCmd, "./docs", emptyStr, anchorLinks)
	if err != nil {
		panic(err)
	}
	combined := ""
	for _, file := range files {
		f, err := os.ReadFile(file)
		if err != nil {
			panic(err)
		}
		combined += string(f) + "\n\n"
	}
	if err = os.WriteFile(files[0], []byte(combined), 0644); err != nil {
		panic(err)
	}
	for _, file := range files[1:] {
		os.Remove(file)
	}
}

func genMarkdownTreeCustom(
	cmd *cobra.Command,
	dir string,
	filePrepender, linkHandler func(string) string,
) ([]string, error) {
	fmt.Println("handling command", cmd.CommandPath())
	basename := strings.ReplaceAll(cmd.CommandPath(), " ", "_") + ".mdx"
	filename := filepath.Join(dir, basename)
	f, err := os.Create(filename)
	if err != nil {
		return []string{}, err
	}
	defer f.Close()

	if _, err := io.WriteString(f, filePrepender(filename)); err != nil {
		return []string{}, err
	}
	if err := doc.GenMarkdownCustom(cmd, f, linkHandler); err != nil {
		return []string{}, err
	}

	newFiles := []string{filename}
	for _, c := range cmd.Commands() {
		if !c.IsAvailableCommand() || c.IsAdditionalHelpTopicCommand() {
			continue
		}
		if files, err := genMarkdownTreeCustom(c, dir, filePrepender, linkHandler); err != nil {
			return newFiles, err
		} else {
			newFiles = append(newFiles, files...)
		}
	}
	return newFiles, nil
}
