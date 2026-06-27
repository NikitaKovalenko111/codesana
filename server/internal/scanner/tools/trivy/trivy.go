package scanner_trivy

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

type TrivyReport struct {
	CreatedAt time.Time           `json:"CreatedAt"`
	Metadata  TrivyReportMetadata `json:"Metadata"`
	Results   []TrivyReportResult `json:"Results"`
}

type TrivyReportMetadata struct {
	Branch    string `json:"Branch"`
	Commit    string `json:"Commit"`
	Author    string `json:"Author"`
	Committer string `json:"Committer"`
}

type TrivyReportResult struct {
	Target          string                     `json:"Target"`
	Vulnerabilities []TrivyReportVulnerability `json:"Vulnerabilities"`
}

type TrivyReportVulnerability struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title"`
}

type TrivyScanner struct {
	Path string
}

func Init(wd string) *TrivyScanner {
	goos := runtime.GOOS

	var ext string

	switch goos {
	case "windows":
		ext = ".exe"
	case "darwin", "linux":
		ext = ""
	}

	execPath := filepath.Join(filepath.Dir(wd), "utils", "trivy", "trivy"+ext)

	return &TrivyScanner{
		Path: execPath,
	}
}

func (s *TrivyScanner) Scan() *TrivyReport {
	var result TrivyReport

	wd, err := os.Getwd()

	if err != nil {
		panic(err)
	}

	cmd := exec.Command(
		s.Path,
		"fs",
		"--scanners",
		"vuln",
		"--format",
		"json",
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

	err = os.MkdirAll(filepath.Join(wd, ".codesana", "trivy", "results"), 0o644)

	if err != nil {
		panic(err)
	}

	err = os.WriteFile(filepath.Join(wd, ".codesana", "trivy", "results", fmt.Sprintf("trivy-result-%s.json", now)), data, 0o644)
	if err != nil {
		panic(err)
	}

	return &result
}
