package scanner_gitleaks

import (
	"encoding/json"
	"fmt"
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
	Path string
}

func Init(wd string) *GitLeaksScanner {
	goos := runtime.GOOS

	var ext string

	switch goos {
	case "windows":
		ext = ".exe"
	case "darwin", "linux":
		ext = ""
	}

	execPath := filepath.Join(filepath.Dir(wd), "utils", "gitleaks", "gitleaks"+ext)

	return &GitLeaksScanner{
		Path: execPath,
	}
}

func (s *GitLeaksScanner) Scan() *[]GitLeaksFinding {
	var result []GitLeaksFinding

	wd, err := os.Getwd()

	if err != nil {
		panic(err)
	}

	now := strconv.FormatInt(time.Now().Unix(), 10)

	err = os.MkdirAll(filepath.Join(wd, ".codesana", "gitleaks", "results"), 0o644)

	if err != nil {
		panic(err)
	}

	cmd := exec.Command(
		s.Path,
		"detect",
		"--source",
		wd,
		"--report-format",
		"json",
		"--report-path",
		filepath.Join(wd, ".codesana", "gitleaks", "results", fmt.Sprintf("gitleaks-result-%s.json", now)),
	)

	err = cmd.Run()

	if err != nil {
		panic(err)
	}

	data, err := os.ReadFile(filepath.Join(wd, ".codesana", "gitleaks", "results", fmt.Sprintf("gitleaks-result-%s.json", now)))

	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(data, &result)

	if err != nil {
		panic(err)
	}

	return &result
}
