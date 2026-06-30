package scanner_hooks

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	scanner_parser "github.com/NikitaKovalenko111/codesana/internal/scanner/cli/parser"
)

type HooksWorker struct {
	command *scanner_parser.Command
	wd      string
}

func Init(cmd *scanner_parser.Command, wd string) *HooksWorker {
	return &HooksWorker{
		command: cmd,
		wd:      wd,
	}
}

func (w *HooksWorker) Install() {
	err := os.Mkdir(filepath.Join(filepath.Join(w.wd, ".."), ".git", "hooks"), 0644)
	if err != nil {
		if !errors.Is(err, os.ErrExist) {
			panic(err)
		}
	}

	content := []byte(strings.TrimSpace(
		`
	#!/bin/sh

	codesana scan --diff
	STATUS=$?

	if [ $STATUS -ne 0 ]; then
		echo ""
		echo "Commit blocked by Codesana"
		exit 1
	fi

	exit 0
	`,
	))

	err = os.WriteFile(filepath.Join(filepath.Join(w.wd, ".."), ".git", "hooks", "pre-commit"), content, 0755)
	if err != nil {
		panic(err)
	}
}

func (w *HooksWorker) Remove() {
	err := os.Remove(filepath.Join(filepath.Join(w.wd, ".."), ".git", "hooks", "pre-commit"))
	if err != nil {
		panic(err)
	}
}
