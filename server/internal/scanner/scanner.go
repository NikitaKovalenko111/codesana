package main

import (
	"os"

	scanner_parser "github.com/NikitaKovalenko111/codesana/internal/scanner/cli/parser"
	scanner_gitleaks "github.com/NikitaKovalenko111/codesana/internal/scanner/tools/gitleaks"
	scanner_opengrep "github.com/NikitaKovalenko111/codesana/internal/scanner/tools/opengrep"
	scanner_workers "github.com/NikitaKovalenko111/codesana/internal/scanner/workers"
)

func main() {
	command := scanner_parser.Parse()

	wd, err := os.Getwd()

	if err != nil {
		panic(err)
	}

	opengrep := scanner_opengrep.Init()
	gitleaks := scanner_gitleaks.Init(wd)

	workers := scanner_workers.Init(command, opengrep, gitleaks)
	workers.Run()
}
