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
	Path string
}

func Init() *OpengrepScanner {
	mainExe, err := os.Getwd()

	if err != nil {
		panic(err)
	}

	goos := runtime.GOOS

	var ext string

	switch goos {
	case "windows":
		ext = ".exe"
	case "darwin", "linux":
		ext = ""
	}

	opengrepExec := filepath.Join(filepath.Dir(mainExe), "utils", "opengrep", "opengrep"+ext)

	return &OpengrepScanner{
		Path: opengrepExec,
	}
}

func (s *OpengrepScanner) Scan() *OpengrepScanResults {
	var result OpengrepScanResults

	wd, err := os.Getwd()

	if err != nil {
		panic(err)
	}

	cmd := exec.Command(
		s.Path,
		"scan",
		"--json",
		wd,
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

	err = os.MkdirAll(filepath.Join(wd, ".codesana", "opengrep", "results"), 0o644)

	if err != nil {
		panic(err)
	}

	err = os.WriteFile(filepath.Join(wd, ".codesana", "opengrep", "results", fmt.Sprintf("opengrep-result-%s.json", now)), data, 0o644)
	if err != nil {
		panic(err)
	}

	return &result
}
