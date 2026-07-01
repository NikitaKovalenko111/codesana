package scanner

import (
	"fmt"
	"os"
	"path/filepath"

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

	var codesanaWD string

	codesanaWD, err = findCodesanaDir(wd)
	if err != nil {
		codesanaWD = ""
	}

	cfg := scanner_config.Parse(codesanaWD)

	opengrep := scanner_opengrep.Init(exec, wd, codesanaWD)
	gitleaks := scanner_gitleaks.Init(exec, wd, codesanaWD)
	trivy := scanner_trivy.Init(exec, wd, codesanaWD)

	toolsDir := "utils"

	workers := scanner_workers.Init(command, cfg, opengrep, gitleaks, trivy, exec, codesanaWD, toolsDir)
	workers.Run()
}

func findCodesanaDir(start string) (string, error) {
	dir := start

	for {
		codesanaPath := filepath.Join(dir, ".codesana")
		if info, err := os.Stat(codesanaPath); err == nil && info.IsDir() {
			return codesanaPath, nil
		}

		gitPath := filepath.Join(dir, ".git")
		if info, err := os.Stat(gitPath); err == nil && info.IsDir() {
			return "", fmt.Errorf(".codesana not found (reached git root: %s)", dir)
		}

		parent := filepath.Dir(dir)

		if parent == dir {
			return "", fmt.Errorf(".codesana not found (reached filesystem root)")
		}

		dir = parent
	}
}
