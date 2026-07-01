package scanner_hooks

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	scanner_parser "github.com/NikitaKovalenko111/codesana/internal/scanner/cli/parser"
	scanner_errors "github.com/NikitaKovalenko111/codesana/internal/scanner/errors"
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
	err := os.Mkdir(filepath.Join(filepath.Join(w.wd, ".."), ".git", "hooks"), 0755)
	if err != nil {
		if !errors.Is(err, os.ErrExist) {
			scanner_errors.Fatal("Не удалось создать git hooks directory", err, "Проверьте, что проект находится внутри git-репозитория")
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
		scanner_errors.Fatal("Не удалось записать pre-commit hook", err, "Проверьте права доступа к .git/hooks")
	}
}

func (w *HooksWorker) Remove() {
	err := os.Remove(filepath.Join(filepath.Join(w.wd, ".."), ".git", "hooks", "pre-commit"))
	if err != nil {
		scanner_errors.Fatal("Не удалось удалить pre-commit hook", err, "Проверьте, что хук существует и доступен для удаления")
	}
}
