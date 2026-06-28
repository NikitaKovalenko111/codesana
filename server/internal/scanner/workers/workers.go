package scanner_workers

import (
	"fmt"
	"os/exec"
	"strings"

	scanner_parser "github.com/NikitaKovalenko111/codesana/internal/scanner/cli/parser"
	scanner_config "github.com/NikitaKovalenko111/codesana/internal/scanner/config"
	scanner_gitleaks "github.com/NikitaKovalenko111/codesana/internal/scanner/tools/gitleaks"
	scanner_opengrep "github.com/NikitaKovalenko111/codesana/internal/scanner/tools/opengrep"
	scanner_trivy "github.com/NikitaKovalenko111/codesana/internal/scanner/tools/trivy"
	scanner_help "github.com/NikitaKovalenko111/codesana/internal/scanner/workers/help"
	scanner_hooks "github.com/NikitaKovalenko111/codesana/internal/scanner/workers/hooks"
	scanner_init "github.com/NikitaKovalenko111/codesana/internal/scanner/workers/init"
	scanner_scan "github.com/NikitaKovalenko111/codesana/internal/scanner/workers/scan"
	scanner_update "github.com/NikitaKovalenko111/codesana/internal/scanner/workers/update"
)

type Workers struct {
	command      *scanner_parser.Command
	config       *scanner_config.SConfig
	InitWorker   *scanner_init.InitWorker
	UpdateWorker *scanner_update.UpdateWorker
	ScanWorker   *scanner_scan.ScanWorker
	HelpWorker   *scanner_help.HelpWorker
	HooksWorker  *scanner_hooks.HooksWorker
}

func Init(
	cmd *scanner_parser.Command,
	cfg *scanner_config.SConfig,
	opengrep *scanner_opengrep.OpengrepScanner,
	gitleaks *scanner_gitleaks.GitLeaksScanner,
	trivy *scanner_trivy.TrivyScanner,
	exec string,
	wd string,
	toolsDir string,
) *Workers {
	return &Workers{
		command:      cmd,
		config:       cfg,
		InitWorker:   scanner_init.Init(cmd),
		UpdateWorker: scanner_update.Init(cmd, exec, toolsDir),
		ScanWorker:   scanner_scan.Init(cmd, cfg, opengrep, gitleaks, trivy),
		HelpWorker:   scanner_help.Init(),
		HooksWorker:  scanner_hooks.Init(cmd, wd),
	}
}

func (w *Workers) Run() {
	switch w.command.Action {
	case "init":
		w.InitWorker.Run()
	case "update":
		w.UpdateWorker.Run()
	case "hooks":
		if w.command.Subject == "install" {
			w.HooksWorker.Install()
		}

		if w.command.Subject == "remove" {
			w.HooksWorker.Remove()
		}
	case "scan":
		if w.config == nil {
			fmt.Println("Проект не инициализирован...")
			fmt.Println("Пропишите codesana init для инициализации")

			return
		}

		files := make([]string, 0)

		var hasDiffFlag bool = false

		for _, fl := range w.command.Flags {
			if fl == "--diff" {
				hasDiffFlag = true
				break
			}
		}

		if hasDiffFlag {
			out, err := exec.Command(
				"git",
				"diff",
				"--cached",
				"--name-only",
				"--diff-filter=ACMR",
			).Output()

			if err != nil {
				panic(err)
			}

			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					files = append(files, line)
				}
			}
		}

		w.ScanWorker.Run(files)
	case "help":
		w.HelpWorker.Run(w.command)
	}
}
