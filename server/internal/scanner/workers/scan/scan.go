package scanner_scan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	scanner_parser "github.com/NikitaKovalenko111/codesana/internal/scanner/cli/parser"
	scanner_config "github.com/NikitaKovalenko111/codesana/internal/scanner/config"
	scanner_gitleaks "github.com/NikitaKovalenko111/codesana/internal/scanner/tools/gitleaks"
	scanner_opengrep "github.com/NikitaKovalenko111/codesana/internal/scanner/tools/opengrep"
	scanner_trivy "github.com/NikitaKovalenko111/codesana/internal/scanner/tools/trivy"
	scanner_ignore "github.com/NikitaKovalenko111/codesana/internal/scanner/workers/ignore"
)

type ScanWorker struct {
	command         *scanner_parser.Command
	ignoreMap       map[string]scanner_ignore.IgnoredVuln
	config          *scanner_config.SConfig
	opengrepScanner *scanner_opengrep.OpengrepScanner
	gitleaksScanner *scanner_gitleaks.GitLeaksScanner
	trivyScanner    *scanner_trivy.TrivyScanner
}

type hashData struct {
	FactorF string
	FactorS string
}

func Init(
	cmd *scanner_parser.Command,
	cfg *scanner_config.SConfig,
	opengrep *scanner_opengrep.OpengrepScanner,
	gitleaks *scanner_gitleaks.GitLeaksScanner,
	trivy *scanner_trivy.TrivyScanner,
	ignoreMap map[string]scanner_ignore.IgnoredVuln,
) *ScanWorker {
	return &ScanWorker{
		command:         cmd,
		config:          cfg,
		opengrepScanner: opengrep,
		gitleaksScanner: gitleaks,
		trivyScanner:    trivy,
		ignoreMap:       ignoreMap,
	}
}

func (w *ScanWorker) Run(files []string) {
	var opengrepReport *scanner_opengrep.OpengrepScanResults
	var gitleaksReport *[]scanner_gitleaks.GitLeaksFinding
	var trivyReport *scanner_trivy.TrivyReport

	var vulns int = 0

	if w.config.UseOpengrep {
		opengrepReport = w.opengrepScanner.Scan(files)
	}

	if w.config.UseGitLeaks {
		gitleaksReport = w.gitleaksScanner.Scan(files)
	}

	if w.config.UseTrivy {
		trivyReport = w.trivyScanner.Scan(files)
	}

	if opengrepReport != nil {
		fmt.Println("----------------------------------------------------------------")
		fmt.Print("Результат сканирования на основные уязвимости:\n")
		fmt.Print("Сканнер: opengrep\n")
		fmt.Printf("Версия opengrep: %s\n\n", opengrepReport.Version)

		var unignoredCount int = 0

		for _, result := range opengrepReport.Results {
			hashData := hashData{
				FactorF: result.CheckId,
				FactorS: result.Extra.Message,
			}

			data, err := json.Marshal(hashData)
			if err != nil {
				panic(err)
			}

			vulnHash := sha256.Sum256(data)
			vulnHashString := hex.EncodeToString(vulnHash[:])
			if _, ok := w.ignoreMap[vulnHashString]; ok {
				continue
			}

			if result.Extra.Severity == "ERROR" {
				vulns += 1
			}

			fmt.Printf("Хеш проверки: %s\n", vulnHashString)
			fmt.Printf("Проверенный файл: %s\n", result.Path)
			fmt.Printf("Сообщение: %s\n", result.Extra.Message)
			if result.Extra.Fix != "" {
				fmt.Printf("Предложенное исправление: %s\n", result.Extra.Fix)
			}
			if result.Extra.Severity == "ERROR" {
				fmt.Printf("Уровень опасности: \x1b[31m%s\x1b[0m\n", result.Extra.Severity)
			}
			if result.Extra.Severity == "WARNING" {
				fmt.Printf("Уровень опасности: \x1b[33m%s\x1b[0m\n", result.Extra.Severity)
			}
			if result.Extra.Severity == "INFO" {
				fmt.Printf("Уровень опасности: \x1b[34m%s\x1b[0m\n", result.Extra.Severity)
			}
			fmt.Printf("\n")

			unignoredCount += 1
		}

		if unignoredCount == 0 {
			fmt.Print("\x1b[32mУязвимости не найдены!\x1b[0m")
		}

		fmt.Print("\n")
	}

	if gitleaksReport != nil {
		fmt.Println("----------------------------------------------------------------")
		fmt.Print("Результат сканирования на слитые секреты:\n")
		fmt.Print("Сканнер: gitleaks\n\n")

		var unignoredCount int = 0

		for _, result := range *gitleaksReport {
			hashData := hashData{
				FactorF: result.Finding,
				FactorS: result.File,
			}

			data, err := json.Marshal(hashData)
			if err != nil {
				panic(err)
			}

			vulnHash := sha256.Sum256(data)
			vulnHashString := hex.EncodeToString(vulnHash[:])
			if _, ok := w.ignoreMap[vulnHashString]; ok {
				continue
			}

			vulns += 1

			fmt.Printf("Хеш секрета: %s\n", vulnHashString)
			fmt.Printf("Уязвимость: %s\n", result.Finding)
			fmt.Printf("Проверенный файл: %s\n", result.File)
			fmt.Printf("Коммит: %s\n", result.Commit)
			fmt.Printf("Автор коммита: %s\n", result.Author)
			fmt.Printf("Почта автора: %s\n", result.Email)

			unignoredCount += 1
		}

		if unignoredCount == 0 {
			fmt.Print("\x1b[32mСекреты не найдены!\x1b[0m")
		}

		fmt.Print("\n")
	}

	if trivyReport != nil {
		fmt.Println("----------------------------------------------------------------")
		fmt.Print("Результат сканирования на CVE:\n")
		fmt.Print("Сканнер: trivy\n\n")

		for _, result := range trivyReport.Results {
			fmt.Printf("Файл: %s\n", result.Target)

			var unignoredCount int = 0

			for idx, vuln := range result.Vulnerabilities {
				hashData := hashData{
					FactorF: vuln.VulnerabilityID,
					FactorS: vuln.PkgName,
				}

				data, err := json.Marshal(hashData)
				if err != nil {
					panic(err)
				}

				vulnHash := sha256.Sum256(data)
				vulnHashString := hex.EncodeToString(vulnHash[:])
				if _, ok := w.ignoreMap[vulnHashString]; ok {
					continue
				}

				if vuln.Severity == "CRITICAL" || vuln.Severity == "HIGH" {
					vulns += 1
				}

				fmt.Printf("\t- Уязвимость %d:\n", idx+1)
				fmt.Printf("\t\tНазвание: %s\n", vuln.Title)
				fmt.Printf("\t\tПакет: %s\n", vuln.PkgName)
				fmt.Printf("\t\tВерсия пакета: %s\n", vuln.InstalledVersion)
				fmt.Printf("\t\tВерсия пакета с фиксом: %s\n", vuln.FixedVersion)

				if vuln.Severity == "CRITICAL" || vuln.Severity == "HIGH" {
					fmt.Printf("\t\tУровень опасности: \x1b[31m%s\x1b[0m\n", vuln.Severity)
				}
				if vuln.Severity == "MEDIUM" {
					fmt.Printf("\t\tУровень опасности: \x1b[33m%s\x1b[0m\n", vuln.Severity)
				}
				if vuln.Severity == "LOW" || vuln.Severity == "UNKNOWN" {
					fmt.Printf("\t\tУровень опасности: \x1b[34m%s\x1b[0m\n", vuln.Severity)
				}

				unignoredCount += 1
			}

			if unignoredCount == 0 {
				fmt.Print("\x1b[32mУязвимости не найдены!\x1b[0m")
			}
		}

		fmt.Print("\n")

		if vulns > 0 {
			os.Exit(1)
		}

		os.Exit(0)
	}
}
