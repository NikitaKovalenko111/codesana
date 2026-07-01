package scanner_gitleaks

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
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
	sourceRoot := filepath.Join(s.wd, path)

	if err := os.RemoveAll(tmpDir); err != nil && !errors.Is(err, os.ErrNotExist) {
		scanner_errors.Print("Не удалось подготовить временную папку gitleaks", err, "Сканирование секретов будет пропущено")
		return nil
	}

	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		scanner_errors.Print("Не удалось подготовить временную папку gitleaks", err, "Сканирование секретов будет пропущено")
		return nil
	}

	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	if len(files) > 0 {
		for _, f := range files {
			if pathContainsSegment(f, ".codesana") {
				continue
			}

			srcPath := filepath.Join(s.codesanaWD, "..", f)
			dstPath := filepath.Join(tmpDir, f)

			if err := copyFile(srcPath, dstPath); err != nil {
				scanner_errors.Print("Не удалось подготовить временный файл для gitleaks", err, "Сканирование секретов будет пропущено")
				return nil
			}
		}
	} else {
		if err := copyDirWithoutSegment(sourceRoot, tmpDir, ".codesana"); err != nil {
			scanner_errors.Print("Не удалось подготовить временную копию для gitleaks", err, "Сканирование секретов будет пропущено")
			return nil
		}
	}

	now := strconv.FormatInt(time.Now().Unix(), 10)

	if err := os.MkdirAll(filepath.Join(s.codesanaWD, "gitleaks", "results"), 0755); err != nil {
		scanner_errors.Print("Не удалось создать папку результатов gitleaks", err, "Сканирование секретов будет пропущено")
		return nil
	}

	cmd := exec.Command(
		s.exec,
		"detect",
		"--source",
		tmpDir,
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

	if err := json.Unmarshal(data, &result); err != nil {
		scanner_errors.Print("Не удалось разобрать отчет gitleaks", err, "Сканирование секретов будет пропущено")
		return nil
	}

	return &result
}

func copyFile(srcPath, dstPath string) error {
	if err := os.MkdirAll(filepath.Dir(dstPath), 0755); err != nil {
		return err
	}

	in, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}

	return out.Sync()
}

func copyDirWithoutSegment(sourceRoot, destRoot, ignoredSegment string) error {
	return filepath.WalkDir(sourceRoot, func(currentPath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		relPath, err := filepath.Rel(sourceRoot, currentPath)
		if err != nil {
			return err
		}

		if relPath == "." {
			return nil
		}

		if pathContainsSegment(relPath, ignoredSegment) {
			if entry.IsDir() {
				return filepath.SkipDir
			}

			return nil
		}

		targetPath := filepath.Join(destRoot, relPath)
		if entry.IsDir() {
			return os.MkdirAll(targetPath, 0755)
		}

		return copyFile(currentPath, targetPath)
	})
}

func pathContainsSegment(path string, segment string) bool {
	normalized := filepath.ToSlash(filepath.Clean(path))
	for _, part := range strings.Split(normalized, "/") {
		if part == segment {
			return true
		}
	}

	return false
}
