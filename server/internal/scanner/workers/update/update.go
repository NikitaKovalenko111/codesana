package scanner_update

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	scanner_parser "github.com/NikitaKovalenko111/codesana/internal/scanner/cli/parser"
	"github.com/cavaliergopher/grab/v3"
)

type UpdateWorker struct {
	command *scanner_parser.Command
}

func Init(cmd *scanner_parser.Command) *UpdateWorker {
	return &UpdateWorker{
		command: cmd,
	}
}

func (w *UpdateWorker) Run() {
	if !w.isToolInstalled("opengrep") {
		fmt.Println("Opengrep не установлен! Установка...")

		url, err := w.buildDownloadURL("opengrep")

		if err != nil {
			fmt.Println("Ошибка установки opengrep")

			return
		}

		exe, err := os.Getwd()

		if err != nil {
			panic(exe)
		}

		exe, _ = filepath.EvalSymlinks(exe)
		cwd := filepath.Dir(exe)

		toolsDir := "utils"

		var ext string
		goos := runtime.GOOS

		switch goos {
		case "linux", "darwin":
			ext = ".tar.gz"
		case "windows":
			ext = ".zip"
		}

		dst, err := w.downloadFile(url, fmt.Sprintf("%s/%s/temp/opengrep", cwd, toolsDir), ext)

		if err != nil {
			panic(err)
		}

		instDir := fmt.Sprintf("%s/%s/opengrep", cwd, toolsDir)

		err = w.installFromArchive("opengrep", dst, instDir)

		if err != nil {
			panic(err)
		}

		err = os.RemoveAll(fmt.Sprintf("%s/%s/temp", cwd, toolsDir))

		if err != nil {
			panic(err)
		}
	}

	if !w.isToolInstalled("trivy") {
		fmt.Println("Trivy не установлен! Установка...")

		url, err := w.buildDownloadURL("trivy")

		if err != nil {
			fmt.Println("Ошибка установки trivy")

			return
		}

		exe, err := os.Getwd()

		if err != nil {
			panic(exe)
		}

		exe, _ = filepath.EvalSymlinks(exe)
		cwd := filepath.Dir(exe)

		toolsDir := "utils"

		var ext string
		goos := runtime.GOOS

		switch goos {
		case "linux", "darwin":
			ext = ".tar.gz"
		case "windows":
			ext = ".zip"
		}

		dst, err := w.downloadFile(url, fmt.Sprintf("%s/%s/temp/trivy", cwd, toolsDir), ext)

		if err != nil {
			panic(err)
		}

		instDir := fmt.Sprintf("%s/%s/trivy", cwd, toolsDir)

		err = w.installFromArchive("trivy", dst, instDir)

		if err != nil {
			panic(err)
		}

		err = os.RemoveAll(fmt.Sprintf("%s/%s/temp", cwd, toolsDir))

		if err != nil {
			panic(err)
		}
	}

	if !w.isToolInstalled("gitleaks") {
		fmt.Println("Gitleaks не установлен! Установка...")

		url, err := w.buildDownloadURL("gitleaks")

		fmt.Print(url)

		if err != nil {
			fmt.Println("Ошибка установки gitleaks")

			return
		}

		exe, err := os.Getwd()

		if err != nil {
			panic(exe)
		}

		exe, _ = filepath.EvalSymlinks(exe)
		cwd := filepath.Dir(exe)

		toolsDir := "utils"

		var ext string
		goos := runtime.GOOS

		switch goos {
		case "linux", "darwin":
			ext = ".tar.gz"
		case "windows":
			ext = ".zip"
		}

		dst, err := w.downloadFile(url, fmt.Sprintf("%s/%s/temp/gitleaks", cwd, toolsDir), ext)

		if err != nil {
			panic(err)
		}

		instDir := fmt.Sprintf("%s/%s/gitleaks", cwd, toolsDir)

		err = w.installFromArchive("gitleaks", dst, instDir)

		if err != nil {
			panic(err)
		}

		err = os.RemoveAll(fmt.Sprintf("%s/%s/temp", cwd, toolsDir))

		if err != nil {
			panic(err)
		}
	}
}

func (w *UpdateWorker) isToolInstalled(toolName string) bool {
	exe, err := os.Getwd()

	if err != nil {
		panic("couldn't find executable file")
	}

	exe, _ = filepath.EvalSymlinks(exe)
	cwd := filepath.Dir(exe)

	toolsDir := "toolst"

	switch toolName {
	case "opengrep":
		if _, err := os.Stat(fmt.Sprintf("%s/%s/opengrep", cwd, toolsDir)); os.IsNotExist(err) {
			return false
		}
	case "trivy":
		if _, err := os.Stat(fmt.Sprintf("%s/%s/trivy", cwd, toolsDir)); os.IsNotExist(err) {
			return false
		}
	case "gitleaks":
		if _, err := os.Stat(fmt.Sprintf("%s/%s/gitleaks", cwd, toolsDir)); os.IsNotExist(err) {
			return false
		}
	}

	return true
}

func (w *UpdateWorker) buildDownloadURL(toolName string) (string, error) {
	goos := runtime.GOOS
	arch := runtime.GOARCH

	var version, downloadURL, ext string

	switch goos {
	case "linux", "darwin":
		ext = "tar.gz"
	case "windows":
		ext = "zip"
	default:
		return "", errors.New("unsupported OS: " + goos)
	}

	switch toolName {
	case "opengrep":
		version = "1.23.0"
		downloadURL = "https://github.com/opengrep/opengrep"

		if goos == "windows" {
			arch = "x86"
		}

		if arch == "arm64" {
			arch = "aarch64"
		}

		return fmt.Sprintf("%s/releases/download/v%s/%s-core_%s_%s.%s",
			downloadURL, version, toolName, goos, arch, ext), nil
	case "trivy":
		version = "0.71.2"
		downloadURL = "https://github.com/aquasecurity/trivy"

		goos = strings.ToUpper(goos[:1]) + goos[1:]

		if strings.Contains(arch, "arm") {
			arch = strings.ToUpper(arch)
		}

		if strings.Contains(arch, "x") {
			arch = fmt.Sprintf("%sbit", arch[1:])
		}

		if arch == "amd64" {
			arch = "64bit"
		}

		return fmt.Sprintf("%s/releases/download/v%s/%s_%s_%s-%s.%s",
			downloadURL, version, toolName, version, goos, arch, ext), nil
	case "gitleaks":
		version = "8.30.1"
		downloadURL = "https://github.com/gitleaks/gitleaks"

		if arch == "amd64" {
			arch = "x64"
		}

		return fmt.Sprintf("%s/releases/download/v%s/%s_%s_%s_%s.%s",
			downloadURL, version, toolName, version, goos, arch, ext), nil
	}

	return "", errors.New("unsupported OS")
}

func (w *UpdateWorker) downloadFile(url, dst, ext string) (string, error) {
	fulldst := dst + ext

	resp, err := grab.Get(fulldst, url)

	if err != nil {
		return "", fmt.Errorf("download failed: %w", err)
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			fmt.Printf(
				"%.2f%%\n",
				100*resp.Progress(),
			)

		case <-resp.Done:
			if err := resp.Err(); err != nil {
				return "", err
			}
			return fulldst, nil
		}
	}
}

func (w *UpdateWorker) installFromArchive(toolName, archivePath, installDir string) error {
	ext := filepath.Ext(archivePath)
	base := filepath.Base(archivePath)

	if ext == ".zip" {
		return w.installFromZip(archivePath, installDir)
	}

	if filepath.Ext(base) == ".gz" && (len(base) >= 7 && base[len(base)-7:] == ".tar.gz") {
		return w.installFromTarGz(toolName, archivePath, installDir)
	}

	return errors.New("unsupported archive format: " + archivePath)
}

func (w *UpdateWorker) installFromZip(zipPath, installDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		path := filepath.Join(installDir, f.Name)

		if !strings.HasPrefix(
			filepath.Clean(path),
			filepath.Clean(installDir)+string(os.PathSeparator),
		) {
			return fmt.Errorf("invalid zip entry: %s", f.Name)
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(path, 0o755); err != nil {
				return err
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}

		out, err := os.OpenFile(
			path,
			os.O_CREATE|os.O_WRONLY|os.O_TRUNC,
			f.Mode(),
		)
		if err != nil {
			rc.Close()
			return err
		}

		_, err = io.Copy(out, rc)

		rc.Close()
		out.Close()

		if err != nil {
			return err
		}
	}

	return nil
}

func (w *UpdateWorker) installFromTarGz(toolName, tarGzPath, installDir string) error {
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		tmpDir, err := os.MkdirTemp("", "tool-install-*")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmpDir)

		cmd := exec.Command("tar", "-xzf", tarGzPath, "-C", tmpDir)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("tar failed: %w: %s", err, string(out))
		}

		var found string
		_ = filepath.Walk(tmpDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info != nil && !info.IsDir() && filepath.Base(path) == toolName {
				found = path
				return io.EOF
			}
			return nil
		})

		if found == "" {
			return errors.New("binary not found in tar.gz")
		}

		dst := filepath.Join(installDir, toolName)
		return w.copyFileAndChmod(found, dst, 0o755)
	}

	return errors.New("tar.gz not supported on this OS in this example")
}

func (w *UpdateWorker) copyFileAndChmod(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return os.Chmod(dst, mode)
}
