package scanner_workers

import (
	scanner_parser "github.com/NikitaKovalenko111/codesana/internal/scanner/cli/parser"
	scanner_opengrep "github.com/NikitaKovalenko111/codesana/internal/scanner/tools/opengrep"
	scanner_init "github.com/NikitaKovalenko111/codesana/internal/scanner/workers/init"
	scanner_scan "github.com/NikitaKovalenko111/codesana/internal/scanner/workers/scan"
	scanner_update "github.com/NikitaKovalenko111/codesana/internal/scanner/workers/update"
)

type Workers struct {
	command      *scanner_parser.Command
	InitWorker   *scanner_init.InitWorker
	UpdateWorker *scanner_update.UpdateWorker
	ScanWorker   *scanner_scan.ScanWorker
}

func Init(cmd *scanner_parser.Command, opengrep *scanner_opengrep.OpengrepScanner) *Workers {
	return &Workers{
		command:      cmd,
		InitWorker:   scanner_init.Init(cmd),
		UpdateWorker: scanner_update.Init(cmd),
		ScanWorker:   scanner_scan.Init(cmd, opengrep),
	}
}

func (w *Workers) Run() {
	switch w.command.Action {
	case "init":
		w.InitWorker.Run()
	case "update":
		w.UpdateWorker.Run()
	case "scan":
		w.ScanWorker.Run()
	}
}
