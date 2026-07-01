package scanner_ignore

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	scanner_parser "github.com/NikitaKovalenko111/codesana/internal/scanner/cli/parser"
	scanner_errors "github.com/NikitaKovalenko111/codesana/internal/scanner/errors"
)

type IgnoredVuln struct {
	Fingerprint string `json:"fingerprint"`
	Reason      string `json:"reason"`
}

type IgnoredFileJSON struct {
	Ignored []IgnoredVuln `json:"ignored"`
}

type IgnoreWorker struct {
	wd        string
	cmd       *scanner_parser.Command
	IgnoreMap map[string]IgnoredVuln
}

func Init(wd string, cmd *scanner_parser.Command) *IgnoreWorker {
	var ignoredData IgnoredFileJSON

	if wd != "" {
		if !isIgnoreFileExist(wd) {
			dataBytes, err := json.Marshal(ignoredData)
			if err != nil {
				scanner_errors.Fatal("Не удалось создать ignore.json", err, "Проверьте права доступа к рабочей директории")
			}

			err = os.WriteFile(filepath.Join(wd, "ignore.json"), dataBytes, 0755)
			if err != nil {
				scanner_errors.Fatal("Не удалось записать ignore.json", err, "Проверьте права доступа к рабочей директории")
			}
		}

		data, err := os.ReadFile(filepath.Join(wd, "ignore.json"))
		if err != nil {
			scanner_errors.Fatal("Не удалось прочитать ignore.json", err, "Запустите codesana init заново")
		}

		err = json.Unmarshal(data, &ignoredData)
		if err != nil {
			scanner_errors.Fatal("Некорректный ignore.json", err, "Проверьте структуру файла .codesana/ignore.json")
		}
	}

	var ignoredMap = make(map[string]IgnoredVuln)

	if wd != "" {
		for _, i := range ignoredData.Ignored {
			ignoredMap[i.Fingerprint] = i
		}
	}

	return &IgnoreWorker{
		wd:        wd,
		cmd:       cmd,
		IgnoreMap: ignoredMap,
	}
}

func (w *IgnoreWorker) Run() {
	var ignoredData IgnoredFileJSON

	data, err := os.ReadFile(filepath.Join(w.wd, "ignore.json"))
	if err != nil {
		scanner_errors.Fatal("Не удалось прочитать ignore.json", err, "Проверьте права доступа к файлу")
	}

	err = json.Unmarshal(data, &ignoredData)
	if err != nil {
		scanner_errors.Fatal("Некорректный ignore.json", err, "Проверьте структуру файла .codesana/ignore.json")
	}

	var msg string

	for _, f := range w.cmd.Flags {
		if f.FlagName == "--reason" {
			msg = f.FlagVal
		}
	}

	ignoredData.Ignored = append(ignoredData.Ignored, IgnoredVuln{
		Fingerprint: w.cmd.Subject,
		Reason:      msg,
	})

	newData, err := json.Marshal(ignoredData)
	if err != nil {
		scanner_errors.Fatal("Не удалось сформировать ignore.json", err, "Повторите команду ignore")
	}

	err = os.WriteFile(filepath.Join(w.wd, "ignore.json"), newData, 0755)
	if err != nil {
		scanner_errors.Fatal("Не удалось записать ignore.json", err, "Проверьте права доступа к файлу")
	}
}

func isIgnoreFileExist(wd string) bool {
	_, err := os.Lstat(filepath.Join(wd, "ignore.json"))

	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false
		}

		scanner_errors.Fatal("Не удалось проверить ignore.json", err, "Повторите команду позже")
	}

	return true
}
