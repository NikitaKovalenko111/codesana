package scanner_workers

import scanner_init "github.com/NikitaKovalenko111/codesana/internal/scanner/workers/init"

type Workers struct {
	InitWorker *scanner_init.InitWorker
}

func Init() *Workers {
	return &Workers{
		InitWorker: scanner_init.Init(),
	}
}
