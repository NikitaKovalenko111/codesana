package main

import (
	scanner_parser "github.com/NikitaKovalenko111/codesana/internal/scanner/cli/parser"
	scanner_opengrep "github.com/NikitaKovalenko111/codesana/internal/scanner/tools/opengrep"
	scanner_workers "github.com/NikitaKovalenko111/codesana/internal/scanner/workers"
)

func main() {
	command := scanner_parser.Parse()

	opengrep := scanner_opengrep.Init()

	workers := scanner_workers.Init(command, opengrep)
	workers.Run()
}
