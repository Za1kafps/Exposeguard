package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Za1kafps/exposeguard/internal/model"
	"github.com/Za1kafps/exposeguard/internal/report"
	"github.com/Za1kafps/exposeguard/internal/scan"
	"github.com/Za1kafps/exposeguard/internal/system"
)

const (
	ExitOK     = 0
	ExitFailed = 1
	ExitError  = 2
)

func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 2 {
		printRootHelp(stderr)
		return ExitError
	}
	switch args[1] {
	case "scan":
		return runScan(args, stdout, stderr)
	case "-h", "--help", "help":
		printRootHelp(stdout)
		return ExitOK
	default:
		fmt.Fprintf(stderr, "exposeguard: unknown command %q\n", args[1])
		printRootHelp(stderr)
		return ExitError
	}
}

func runScan(fullArgs []string, stdout, stderr io.Writer) int {
	if wantsHelp(fullArgs[2:]) {
		printScanHelp(stdout)
		return ExitOK
	}

	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { printScanHelp(stderr) }
	formatValue := flags.String("format", "terminal", "report format: terminal, json or markdown")
	output := flags.String("output", "", "write report to path")
	composeFile := flags.String("compose-file", "", "optional Docker Compose file")
	noDocker := flags.Bool("no-docker", false, "skip Docker discovery")
	noFirewall := flags.Bool("no-firewall", false, "skip firewall discovery")
	noListeners := flags.Bool("no-listeners", false, "skip local listener discovery")
	failOnValue := flags.String("fail-on", "none", "exit 1 on findings at or above severity: critical, high, medium, low or none")
	verbose := flags.Bool("verbose", false, "include best-effort warning detail")
	if err := flags.Parse(fullArgs[2:]); err != nil {
		if err == flag.ErrHelp {
			return ExitOK
		}
		return ExitError
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(stderr, "exposeguard scan: unexpected arguments: %s\n", strings.Join(flags.Args(), " "))
		return ExitError
	}

	format, err := report.ParseFormat(*formatValue)
	if err != nil {
		fmt.Fprintf(stderr, "exposeguard scan: %v\n", err)
		return ExitError
	}
	failOn, err := model.ParseFailThreshold(*failOnValue)
	if err != nil {
		fmt.Fprintf(stderr, "exposeguard scan: %v\n", err)
		return ExitError
	}

	result, err := scan.Run(context.Background(), system.NewExecRunner(), scan.Options{
		ComposeFile: *composeFile,
		NoDocker:    *noDocker,
		NoFirewall:  *noFirewall,
		NoListeners: *noListeners,
		Verbose:     *verbose,
	})
	if err != nil {
		fmt.Fprintf(stderr, "exposeguard scan: %v\n", err)
		return ExitError
	}
	data, err := report.RenderWithOptions(format, result, report.RenderOptions{
		Verbose:    *verbose || format != report.FormatTerminal,
		DetailHint: verboseHint(fullArgs),
	})
	if err != nil {
		fmt.Fprintf(stderr, "exposeguard scan: %v\n", err)
		return ExitError
	}
	if *output != "" {
		if err := scan.WriteOutput(*output, data); err != nil {
			fmt.Fprintf(stderr, "exposeguard scan: %v\n", err)
			return ExitError
		}
		fmt.Fprintf(stdout, "Report written to %s\n", *output)
	} else {
		_, _ = stdout.Write(data)
	}

	if model.FailsThreshold(result.Findings, failOn) {
		return ExitFailed
	}
	return ExitOK
}

func wantsHelp(args []string) bool {
	for _, arg := range args {
		if arg == "--help" || arg == "-h" || arg == "help" {
			return true
		}
	}
	return false
}

func verboseHint(args []string) string {
	if len(args) == 0 {
		args = os.Args
	}
	command := displayCommand(args[0])
	parts := []string{command, "scan"}
	for i := 2; i < len(args); i++ {
		arg := args[i]
		if arg == "--verbose" {
			continue
		}
		if arg == "--output" || arg == "-output" {
			i++
			continue
		}
		if strings.HasPrefix(arg, "--output=") {
			continue
		}
		parts = append(parts, shellQuote(arg))
	}
	parts = append(parts, "--verbose")
	return strings.Join(parts, " ")
}

func displayCommand(command string) string {
	if command == "" {
		return "exposeguard"
	}
	if strings.Contains(command, string(os.PathSeparator)) {
		return command
	}
	if filepath.Base(command) == command {
		return command
	}
	return command
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	if strings.ContainsAny(value, " \t\n'\"\\$`!*?[]{}()<>|&;") {
		return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
	}
	return value
}

func printRootHelp(w io.Writer) {
	fmt.Fprintln(w, "ExposeGuard detects accidentally exposed Docker services on self-hosted Linux servers.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  exposeguard <command> [flags]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  scan    Inspect Docker bindings, firewall state and local listeners")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  exposeguard scan")
	fmt.Fprintln(w, "  exposeguard scan --compose-file docker-compose.yml --format markdown --output exposeguard.md")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Flags:")
	fmt.Fprintln(w, "  -h, --help    Show help")
}

func printScanHelp(w io.Writer) {
	fmt.Fprintln(w, "Scan the local host for accidentally exposed Docker services.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  exposeguard scan [flags]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  exposeguard scan")
	fmt.Fprintln(w, "  exposeguard scan --verbose")
	fmt.Fprintln(w, "  exposeguard scan --compose-file examples/exposed-postgres/docker-compose.yml --no-firewall")
	fmt.Fprintln(w, "  exposeguard scan --format json --output exposeguard.json")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Flags:")
	fmt.Fprintln(w, "  --format terminal|json|markdown       Report format (default terminal)")
	fmt.Fprintln(w, "  --output <path>                       Write report to a file")
	fmt.Fprintln(w, "  --compose-file <path>                 Add Docker Compose context")
	fmt.Fprintln(w, "  --no-docker                           Skip Docker discovery")
	fmt.Fprintln(w, "  --no-firewall                         Skip firewall discovery")
	fmt.Fprintln(w, "  --no-listeners                        Skip local listener discovery")
	fmt.Fprintln(w, "  --fail-on critical|high|medium|low|none")
	fmt.Fprintln(w, "                                       Exit 1 when matching findings exist")
	fmt.Fprintln(w, "  --verbose                             Show full terminal diagnostics")
}
