package scanner

import (
	"os"

	scanner_parser "github.com/NikitaKovalenko111/codesana/internal/scanner/cli/parser"
	scanner_config "github.com/NikitaKovalenko111/codesana/internal/scanner/config"
	scanner_gitleaks "github.com/NikitaKovalenko111/codesana/internal/scanner/tools/gitleaks"
	scanner_opengrep "github.com/NikitaKovalenko111/codesana/internal/scanner/tools/opengrep"
	scanner_trivy "github.com/NikitaKovalenko111/codesana/internal/scanner/tools/trivy"
	scanner_workers "github.com/NikitaKovalenko111/codesana/internal/scanner/workers"
)

func Run() {
	command := scanner_parser.Parse()

	exec, err := os.Executable()
	if err != nil {
		panic(err)
	}

	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	cfg := scanner_config.Parse(wd)

	opengrep := scanner_opengrep.Init(exec, wd)
	gitleaks := scanner_gitleaks.Init(exec, wd)
	trivy := scanner_trivy.Init(exec, wd)

	toolsDir := "utils"

	workers := scanner_workers.Init(command, cfg, opengrep, gitleaks, trivy, exec, wd, toolsDir)
	workers.Run()
}
