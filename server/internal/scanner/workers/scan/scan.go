package scanner_scan

import (
	scanner_parser "github.com/NikitaKovalenko111/codesana/internal/scanner/cli/parser"
	scanner_opengrep "github.com/NikitaKovalenko111/codesana/internal/scanner/tools/opengrep"
)

type ScanWorker struct {
	command         *scanner_parser.Command
	opengrepScanner *scanner_opengrep.OpengrepScanner
}

func Init(cmd *scanner_parser.Command, opengrep *scanner_opengrep.OpengrepScanner) *ScanWorker {
	return &ScanWorker{
		command:         cmd,
		opengrepScanner: opengrep,
	}
}

func (w *ScanWorker) Run() {
	w.opengrepScanner.Scan()
}
