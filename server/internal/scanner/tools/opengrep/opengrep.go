package scanner_opengrep

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	scanner_errors "github.com/NikitaKovalenko111/codesana/internal/scanner/errors"
)

type OpengrepScanResults struct {
	Version string                     `json:"version"`
	Results []OpengrepScanSingleResult `json:"results"`
}

type OpengrepScanSingleResult struct {
	CheckId string                `json:"check_id"`
	Path    string                `json:"path"`
	Start   OpengrepScanPos       `json:"start"`
	End     OpengrepScanPos       `json:"end"`
	Extra   OpengrepScanExtraInfo `json:"extra"`
}

type OpengrepScanPos struct {
	Line   int `json:"line"`
	Col    int `json:"col"`
	Offset int `json:"offset"`
}

type OpengrepScanExtraInfo struct {
	Message  string `json:"message"`
	Fix      string `json:"fix"`
	Severity string `json:"severity"`
}

type OpengrepScanner struct {
	exec       string
	wd         string
	codesanaWD string
}

func Init(exec, wd, codesanaWD string) *OpengrepScanner {
	if codesanaWD == "" {
		return nil
	}

	goos := runtime.GOOS

	var ext string

	switch goos {
	case "windows":
		ext = ".exe"
	case "darwin", "linux":
		ext = ""
	}

	opengrepExec := filepath.Join(filepath.Dir(exec), "utils", "opengrep", "opengrep"+ext)

	return &OpengrepScanner{
		exec:       opengrepExec,
		wd:         wd,
		codesanaWD: codesanaWD,
	}
}

func (s *OpengrepScanner) Scan(files []string, path string) *OpengrepScanResults {
	var result OpengrepScanResults

	args := []string{
		"scan",
		"--json",
	}

	if len(files) == 0 {
		args = append(args, filepath.Join(s.wd, path))
	} else {
		for _, f := range files {
			args = append(args, filepath.Join(s.codesanaWD, "..", f))
		}
	}

	cmd := exec.Command(
		s.exec,
		args...,
	)

	data, err := cmd.Output()

	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			stderr := strings.TrimSpace(string(exitErr.Stderr))
			if stderr != "" {
				scanner_errors.Print("Opengrep не смог завершить сканирование", fmt.Errorf("%s", stderr), "Результат opengrep будет пропущен")
			} else {
				scanner_errors.Print("Opengrep не смог завершить сканирование", err, "Результат opengrep будет пропущен")
			}
		} else {
			scanner_errors.Print("Opengrep не смог завершить сканирование", err, "Результат opengrep будет пропущен")
		}

		return nil
	}

	data = bytes.TrimSpace(data)
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})

	err = json.Unmarshal(data, &result)

	if err != nil {
		scanner_errors.Print("Не удалось разобрать отчет opengrep", err, "Результат opengrep будет пропущен")
		return nil
	}

	now := strconv.FormatInt(time.Now().Unix(), 10)

	err = os.MkdirAll(filepath.Join(s.codesanaWD, "opengrep", "results"), 0755)

	if err != nil {
		scanner_errors.Print("Не удалось создать папку результатов opengrep", err, "Результат opengrep будет пропущен")
		return nil
	}

	err = os.WriteFile(filepath.Join(s.codesanaWD, "opengrep", "results", fmt.Sprintf("opengrep-result-%s.json", now)), data, 0755)
	if err != nil {
		scanner_errors.Print("Не удалось сохранить отчет opengrep", err, "Результат opengrep будет пропущен")
		return nil
	}

	return &result
}
