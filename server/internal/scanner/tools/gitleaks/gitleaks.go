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
	Finding string    `json:"finding"`
	Secret  string    `json:"secret"`
	File    string    `json:"file"`
	Line    int       `json:"line"`
	Commit  string    `json:"commit"`
	Author  string    `json:"author"`
	Email   string    `json:"email"`
	Date    time.Time `json:"date"`
}

type GitLeaksScanner struct {
	exec string
	wd   string
}

func Init(exec, wd string) *GitLeaksScanner {
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
		exec: execPath,
		wd:   wd,
	}
}

func (s *GitLeaksScanner) Scan(files []string) *[]GitLeaksFinding {
	var result []GitLeaksFinding

	tmpDir := filepath.Join(s.wd, ".codesana", "gitleaks", "tmp")

	if len(files) > 0 {
		err := os.MkdirAll(filepath.Join(s.wd, ".codesana", "gitleaks", "tmp"), 0o644)
		if err != nil {
			panic(err)
		}

		for _, f := range files {
			src := filepath.Join(s.wd, f)

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

	err := os.MkdirAll(filepath.Join(s.wd, ".codesana", "gitleaks", "results"), 0o644)

	if err != nil {
		panic(err)
	}

	var src string

	if len(files) > 0 {
		src = tmpDir
	} else {
		src = s.wd
	}

	cmd := exec.Command(
		s.exec,
		"detect",
		"--source",
		src,
		"--report-format",
		"json",
		"--report-path",
		filepath.Join(s.wd, ".codesana", "gitleaks", "results", fmt.Sprintf("gitleaks-result-%s.json", now)),
	)

	err = cmd.Run()

	if err != nil {
		panic(err)
	}

	data, err := os.ReadFile(filepath.Join(s.wd, ".codesana", "gitleaks", "results", fmt.Sprintf("gitleaks-result-%s.json", now)))

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
