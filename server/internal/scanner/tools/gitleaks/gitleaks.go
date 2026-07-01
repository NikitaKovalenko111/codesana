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
		err := os.MkdirAll(filepath.Join(s.codesanaWD, "gitleaks", "tmp"), 0o644)
		if err != nil {
			panic(err)
		}

		for _, f := range files {
			src := filepath.Join(filepath.Join(s.codesanaWD, ".."), f)

			in, err := os.Open(src)
			if err != nil {
				panic(err)
			}

			out, err := os.Create(filepath.Join(tmpDir, filepath.Base(f)))
			if err != nil {
				panic(err)
			}
			if _, err := io.Copy(out, in); err != nil {
				panic(err)
			}

			err = out.Sync()
			if err != nil {
				panic(err)
			}

			in.Close()
			out.Close()
		}
	}

	now := strconv.FormatInt(time.Now().Unix(), 10)

	err := os.MkdirAll(filepath.Join(s.codesanaWD, "gitleaks", "results"), 0o644)

	if err != nil {
		panic(err)
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
		panic(err)
	}

	err = json.Unmarshal(data, &result)

	if err != nil {
		panic(err)
	}

	if len(files) > 0 {
		err := os.RemoveAll(tmpDir)
		if err != nil {
			panic(err)
		}
	}

	return &result
}
