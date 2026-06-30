package scanner_ignore

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	scanner_parser "github.com/NikitaKovalenko111/codesana/internal/scanner/cli/parser"
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

	if !isIgnoreFileExist(wd) {
		dataBytes, err := json.Marshal(ignoredData)
		if err != nil {
			panic(err)
		}

		err = os.WriteFile(filepath.Join(wd, "ignore.json"), dataBytes, 0755)
		if err != nil {
			panic(err)
		}
	}

	data, err := os.ReadFile(filepath.Join(wd, "ignore.json"))
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(data, &ignoredData)
	if err != nil {
		panic(err)
	}

	var ignoredMap = make(map[string]IgnoredVuln)

	for _, i := range ignoredData.Ignored {
		ignoredMap[i.Fingerprint] = i
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
		panic(err)
	}

	err = json.Unmarshal(data, &ignoredData)
	if err != nil {
		panic(err)
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
		panic(err)
	}

	err = os.WriteFile(filepath.Join(w.wd, "ignore.json"), newData, 0755)
	if err != nil {
		panic(err)
	}
}

func isIgnoreFileExist(wd string) bool {
	_, err := os.Lstat(filepath.Join(wd, "ignore.json"))

	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false
		}

		panic(err)
	}

	return true
}
