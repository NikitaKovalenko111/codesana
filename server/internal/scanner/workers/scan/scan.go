package scanner_scan

import (
	scanner_parser "github.com/NikitaKovalenko111/codesana/internal/scanner/cli/parser"
	scanner_gitleaks "github.com/NikitaKovalenko111/codesana/internal/scanner/tools/gitleaks"
	scanner_opengrep "github.com/NikitaKovalenko111/codesana/internal/scanner/tools/opengrep"
)

type ScanWorker struct {
	command         *scanner_parser.Command
	opengrepScanner *scanner_opengrep.OpengrepScanner
	gitleaksScanner *scanner_gitleaks.GitLeaksScanner
}

func Init(cmd *scanner_parser.Command, opengrep *scanner_opengrep.OpengrepScanner, gitleaks *scanner_gitleaks.GitLeaksScanner) *ScanWorker {
	return &ScanWorker{
		command:         cmd,
		opengrepScanner: opengrep,
		gitleaksScanner: gitleaks,
	}
}

func (w *ScanWorker) Run() {
	w.opengrepScanner.Scan()
	w.gitleaksScanner.Scan()
}
