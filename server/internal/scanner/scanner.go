package main

import (
	scanner_parser "github.com/NikitaKovalenko111/codesana/internal/scanner/cli/parser"
	scanner_workers "github.com/NikitaKovalenko111/codesana/internal/scanner/workers"
)

func main() {
	command := scanner_parser.Parse()

	workers := scanner_workers.Init(command)
	workers.Run()
}
