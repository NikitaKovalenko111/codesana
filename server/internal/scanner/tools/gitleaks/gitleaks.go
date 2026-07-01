package scanner_gitleaks

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	scanner_errors "github.com/NikitaKovalenko111/codesana/internal/scanner/errors"
)

type GitLeaksFinding struct {
	RuleID string `json:"RuleID"`
	Match  string `json:"Match"`
	Desc   string `json:"Description"`
	Secret string `json:"Secret"`
	File   string `json:"File"`
}

type GitLeaksScanner struct {
	exec       string
	wd         string
	codesanaWD string
}

func Init(exec, wd, codesanaWD string) *GitLeaksScanner {
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

	execPath := filepath.Join(filepath.Dir(exec), "utils", "gitleaks", "gitleaks"+ext)

	return &GitLeaksScanner{
		exec:       execPath,
		wd:         wd,
		codesanaWD: codesanaWD,
	}
}

func (s *GitLeaksScanner) Scan(files []string, path string) *[]GitLeaksFinding {
	var result []GitLeaksFinding

	tmpDir := filepath.Join(s.codesanaWD, "gitleaks", "tmp")

	if len(files) > 0 {
		err := os.MkdirAll(filepath.Join(s.codesanaWD, "gitleaks", "tmp"), 0755)
		if err != nil {
			scanner_errors.Print("Не удалось подготовить временную папку gitleaks", err, "Сканирование секретов будет пропущено")
			return nil
		}

		for _, f := range files {
			src := filepath.Join(filepath.Join(s.codesanaWD, ".."), f)

			in, err := os.Open(src)
			if err != nil {
				scanner_errors.Print("Не удалось открыть файл для gitleaks", err, "Сканирование секретов будет пропущено")
				return nil
			}

			out, err := os.Create(filepath.Join(tmpDir, filepath.Base(f)))
			if err != nil {
				scanner_errors.Print("Не удалось создать временный файл для gitleaks", err, "Сканирование секретов будет пропущено")
				return nil
			}
			if _, err := io.Copy(out, in); err != nil {
				scanner_errors.Print("Не удалось скопировать файл для gitleaks", err, "Сканирование секретов будет пропущено")
				return nil
			}

			err = out.Sync()
			if err != nil {
				scanner_errors.Print("Не удалось синхронизировать временный файл gitleaks", err, "Сканирование секретов будет пропущено")
				return nil
			}

			in.Close()
			out.Close()
		}
	}

	now := strconv.FormatInt(time.Now().Unix(), 10)

	err := os.MkdirAll(filepath.Join(s.codesanaWD, "gitleaks", "results"), 0755)

	if err != nil {
		scanner_errors.Print("Не удалось создать папку результатов gitleaks", err, "Сканирование секретов будет пропущено")
		return nil
	}

	var src string

	if len(files) > 0 {
		src = tmpDir
	} else {
		src = filepath.Join(s.wd, path)
	}

	cmd := exec.Command(
		s.exec,
		"detect",
		"--source",
		src,
		"--no-git",
		"--report-format",
		"json",
		"--report-path",
		filepath.Join(
			s.codesanaWD,
			"gitleaks",
			"results",
			fmt.Sprintf("gitleaks-result-%s.json", now),
		),
	)

	_ = cmd.Run()

	data, err := os.ReadFile(filepath.Join(s.codesanaWD, "gitleaks", "results", fmt.Sprintf("gitleaks-result-%s.json", now)))

	if err != nil {
		scanner_errors.Print("Не удалось прочитать отчет gitleaks", err, "Сканирование секретов будет пропущено")
		return nil
	}

	err = json.Unmarshal(data, &result)

	if err != nil {
		scanner_errors.Print("Не удалось разобрать отчет gitleaks", err, "Сканирование секретов будет пропущено")
		return nil
	}

	if len(files) > 0 {
		err := os.RemoveAll(tmpDir)
		if err != nil {
			scanner_errors.Print("Не удалось удалить временную папку gitleaks", err, "Проверьте папку .codesana/gitleaks/tmp")
		}
	}

	return &result
}
