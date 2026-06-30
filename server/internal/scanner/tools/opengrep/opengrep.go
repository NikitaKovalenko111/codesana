package scanner_opengrep

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
		panic(err)
	}

	err = json.Unmarshal(data, &result)

	if err != nil {
		panic(err)
	}

	now := strconv.FormatInt(time.Now().Unix(), 10)

	err = os.MkdirAll(filepath.Join(s.codesanaWD, "opengrep", "results"), 0o644)

	if err != nil {
		panic(err)
	}

	err = os.WriteFile(filepath.Join(s.codesanaWD, "opengrep", "results", fmt.Sprintf("opengrep-result-%s.json", now)), data, 0o644)
	if err != nil {
		panic(err)
	}

	return &result
}
