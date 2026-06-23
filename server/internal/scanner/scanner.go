package main

import (
	"fmt"

	scanner_parser "github.com/NikitaKovalenko111/codesana/internal/scanner/cli/parser"
	scanner_workers "github.com/NikitaKovalenko111/codesana/internal/scanner/workers"
)

func main() {
	command := scanner_parser.Parse()
	fmt.Println(command)

	workers := scanner_workers.Init(command)
	workers.Run()
}
