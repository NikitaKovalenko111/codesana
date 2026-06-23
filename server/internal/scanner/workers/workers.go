package scanner_workers

import (
	scanner_parser "github.com/NikitaKovalenko111/codesana/internal/scanner/cli/parser"
	scanner_init "github.com/NikitaKovalenko111/codesana/internal/scanner/workers/init"
)

type Workers struct {
	command    *scanner_parser.Command
	InitWorker *scanner_init.InitWorker
}

func Init(cmd *scanner_parser.Command) *Workers {
	return &Workers{
		command:    cmd,
		InitWorker: scanner_init.Init(cmd),
	}
}

func (w *Workers) Run() {
	switch w.command.Action {
	case "init":
		w.InitWorker.Run()
	}
}
