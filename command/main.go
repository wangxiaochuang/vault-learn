package command

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/token"
	colorable "github.com/mattn/go-colorable"
	"github.com/mitchellh/cli"
)

type VaultUI struct {
	cli.Ui
	format   string
	detailed bool
}

const (
	globalFlagOutputCurlString = "output-curl-string"
	globalFlagOutputPolicy     = "output-policy"
	globalFlagFormat           = "format"
	globalFlagDetailed         = "detailed"
)

var globalFlags = []string{
	globalFlagOutputCurlString, globalFlagOutputPolicy, globalFlagFormat, globalFlagDetailed,
}

// p40
func setupEnv(args []string) (retArgs []string, format string, detailed bool, outputCurlString bool, outputPolicy bool) {
	var err error
	var nextArgFormat bool
	var haveDetailed bool

	for _, arg := range args {
		if nextArgFormat {
			nextArgFormat = false
			format = arg
		}

		if arg == "--" {
			break
		}

		if len(args) == 1 && (arg == "-v" || arg == "-version" || arg == "--version") {
			args = []string{"version"}
			break
		}
		if isGlobalFlag(arg, globalFlagOutputCurlString) {
			outputCurlString = true
			continue
		}

		if isGlobalFlag(arg, globalFlagOutputPolicy) {
			outputPolicy = true
			continue
		}

		if isGlobalFlagWithValue(arg, globalFlagFormat) {
			format = getGlobalFlagValue(arg)
		}

		if isGlobalFlag(arg, globalFlagFormat) {
			nextArgFormat = true
		}

		if isGlobalFlagWithValue(arg, globalFlagDetailed) {
			detailed, err = strconv.ParseBool(getGlobalFlagValue(globalFlagDetailed))
			if err != nil {
				detailed = false
			}
			haveDetailed = true
		}

		if isGlobalFlag(arg, globalFlagDetailed) {
			detailed = true
			haveDetailed = true
		}
	}

	envVaultFormat := os.Getenv(EnvVaultFormat)
	if format == "" && envVaultFormat != "" {
		format = envVaultFormat
	}
	format = strings.ToLower(format)
	if format == "" {
		format = "table"
	}

	envVaultDetailed := os.Getenv(EnvVaultDetailed)
	if !haveDetailed && envVaultDetailed != "" {
		detailed, err = strconv.ParseBool(envVaultDetailed)
		if err != nil {
			detailed = false
		}
	}

	return args, format, detailed, outputCurlString, outputPolicy
}

func isGlobalFlag(arg string, flag string) bool {
	return arg == "-"+flag || arg == "--"+flag
}

func isGlobalFlagWithValue(arg string, flag string) bool {
	return strings.HasPrefix(arg, "--"+flag+"=") || strings.HasPrefix(arg, "-"+flag+"=")
}

func getGlobalFlagValue(arg string) string {
	_, value, _ := strings.Cut(arg, "=")

	return value
}

// p133
type RunOptions struct {
	TokenHelper token.TokenHelper
	Stdout      io.Writer
	Stderr      io.Writer
	Address     string
	Client      *api.Client
}

func Run(args []string) int {
	return RunCustom(args, nil)
}

func RunCustom(args []string, runOpts *RunOptions) int {
	if runOpts == nil {
		runOpts = &RunOptions{}
	}

	var format string
	var detailed bool
	var outputCurlString bool
	var outputPolicy bool
	args, format, detailed, outputCurlString, outputPolicy = setupEnv(args)

	useColor := true
	if os.Getenv(EnvVaultCLINoColor) != "" || color.NoColor {
		useColor = false
	}

	if runOpts.Stdout == nil {
		runOpts.Stdout = os.Stdout
	}
	if runOpts.Stderr == nil {
		runOpts.Stderr = os.Stderr
	}

	if useColor && format == "table" {
		if f, ok := runOpts.Stdout.(*os.File); ok {
			runOpts.Stdout = colorable.NewColorable(f)
		}
		if f, ok := runOpts.Stderr.(*os.File); ok {
			runOpts.Stderr = colorable.NewColorable(f)
		}
	} else {
		runOpts.Stdout = colorable.NewNonColorable(runOpts.Stdout)
		runOpts.Stderr = colorable.NewNonColorable(runOpts.Stderr)
	}

	uiErrWriter := runOpts.Stderr
	if outputCurlString || outputPolicy {
		uiErrWriter = &bytes.Buffer{}
	}

	ui := &VaultUI{
		Ui: &cli.ColoredUi{
			ErrorColor: cli.UiColorRed,
			WarnColor:  cli.UiColorYellow,
			Ui: &cli.BasicUi{
				Reader:      bufio.NewReader(os.Stdin),
				Writer:      runOpts.Stdout,
				ErrorWriter: uiErrWriter,
			},
		},
		format:   format,
		detailed: detailed,
	}

	serverCmdUi := &VaultUI{
		Ui: &cli.ColoredUi{
			ErrorColor: cli.UiColorRed,
			WarnColor:  cli.UiColorYellow,
			Ui: &cli.BasicUi{
				Reader: bufio.NewReader(os.Stdin),
				Writer: runOpts.Stdout,
			},
		},
		format: format,
	}

	if _, ok := Formatters[format]; !ok {
		ui.Error(fmt.Sprintf("Invalid output format: %s", format))
		return 1
	}

	initCommands(ui, serverCmdUi, runOpts)

	hiddenCommands := []string{"version"}

	cli := &cli.CLI{
		Name:     "vault",
		Args:     args,
		Commands: Commands,
		HelpFunc: groupedHelpFunc(
			cli.BasicHelpFunc("vault"),
		),
		HelpWriter:                 runOpts.Stderr,
		HiddenCommands:             hiddenCommands,
		Autocomplete:               true,
		AutocompleteNoDefaultFlags: true,
	}

	exitCode, err := cli.Run()
	if outputCurlString {
		return generateCurlString(exitCode, runOpts, uiErrWriter.(*bytes.Buffer))
	} else if outputPolicy {
		return generatePolicy(exitCode, runOpts, uiErrWriter.(*bytes.Buffer))
	} else if err != nil {
		fmt.Fprintf(runOpts.Stderr, "Error executing CLI: %s\n", err.Error())
		return 1
	}

	return exitCode
}

var commonCommands = []string{
	// "read",
	// "write",
	// "delete",
	// "list",
	// "login",
	// "agent",
	"server",
	// "status",
	// "unwrap",
}

func groupedHelpFunc(f cli.HelpFunc) cli.HelpFunc {
	return func(commands map[string]cli.CommandFactory) string {
		var b bytes.Buffer
		tw := tabwriter.NewWriter(&b, 0, 2, 6, ' ', 0)

		fmt.Fprintf(tw, "Usage: vault <command> [args]\n\n")
		fmt.Fprintf(tw, "Common commands:\n")
		for _, v := range commonCommands {
			printCommand(tw, v, commands[v])
		}

		otherCommands := make([]string, 0, len(commands))
		for k := range commands {
			found := false
			for _, v := range commonCommands {
				if k == v {
					found = true
					break
				}
			}

			if !found {
				otherCommands = append(otherCommands, k)
			}
		}
		sort.Strings(otherCommands)

		fmt.Fprintf(tw, "\n")
		fmt.Fprintf(tw, "Other commands:\n")
		for _, v := range otherCommands {
			printCommand(tw, v, commands[v])
		}

		tw.Flush()

		return strings.TrimSpace(b.String())
	}
}

func printCommand(w io.Writer, name string, cmdFn cli.CommandFactory) {
	cmd, err := cmdFn()
	if err != nil {
		panic(fmt.Sprintf("failed to load %q command: %s", name, err))
	}
	fmt.Fprintf(w, "    %s\t%s\n", name, cmd.Synopsis())
}

func generateCurlString(exitCode int, runOpts *RunOptions, preParsingErrBuf *bytes.Buffer) int {
	if exitCode == 0 {
		fmt.Fprint(runOpts.Stderr, "Could not generate cURL command")
		return 1
	}

	if api.LastOutputStringError == nil {
		if exitCode == 127 {
			// Usage, just pass it through
			return exitCode
		}
		runOpts.Stderr.Write(preParsingErrBuf.Bytes())
		runOpts.Stderr.Write([]byte("Unable to generate cURL string from command\n"))
		return exitCode
	}

	cs, err := api.LastOutputStringError.CurlString()
	if err != nil {
		runOpts.Stderr.Write([]byte(fmt.Sprintf("Error creating request string: %s\n", err)))
		return 1
	}

	runOpts.Stdout.Write([]byte(fmt.Sprintf("%s\n", cs)))
	return 0
}

func generatePolicy(exitCode int, runOpts *RunOptions, preParsingErrBuf *bytes.Buffer) int {
	if exitCode == 0 {
		fmt.Fprint(runOpts.Stderr, "Could not generate policy")
		return 1
	}

	if api.LastOutputPolicyError == nil {
		if exitCode == 127 {
			// Usage, just pass it through
			return exitCode
		}
		runOpts.Stderr.Write(preParsingErrBuf.Bytes())
		runOpts.Stderr.Write([]byte("Unable to generate policy from command\n"))
		return exitCode
	}

	hcl, err := api.LastOutputPolicyError.HCLString()
	if err != nil {
		runOpts.Stderr.Write([]byte(fmt.Sprintf("Error assembling policy HCL: %s\n", err)))
		return 1
	}

	runOpts.Stdout.Write([]byte(fmt.Sprintf("%s\n", hcl)))
	return 0
}
