package scanner_scan

import (
	"fmt"

	scanner_parser "github.com/NikitaKovalenko111/codesana/internal/scanner/cli/parser"
	scanner_config "github.com/NikitaKovalenko111/codesana/internal/scanner/config"
	scanner_gitleaks "github.com/NikitaKovalenko111/codesana/internal/scanner/tools/gitleaks"
	scanner_opengrep "github.com/NikitaKovalenko111/codesana/internal/scanner/tools/opengrep"
	scanner_trivy "github.com/NikitaKovalenko111/codesana/internal/scanner/tools/trivy"
)

type ScanWorker struct {
	command         *scanner_parser.Command
	config          *scanner_config.SConfig
	opengrepScanner *scanner_opengrep.OpengrepScanner
	gitleaksScanner *scanner_gitleaks.GitLeaksScanner
	trivyScanner    *scanner_trivy.TrivyScanner
}

func Init(
	cmd *scanner_parser.Command,
	cfg *scanner_config.SConfig,
	opengrep *scanner_opengrep.OpengrepScanner,
	gitleaks *scanner_gitleaks.GitLeaksScanner,
	trivy *scanner_trivy.TrivyScanner,
) *ScanWorker {
	return &ScanWorker{
		command:         cmd,
		config:          cfg,
		opengrepScanner: opengrep,
		gitleaksScanner: gitleaks,
		trivyScanner:    trivy,
	}
}

func (w *ScanWorker) Run() {
	var opengrepReport *scanner_opengrep.OpengrepScanResults
	var gitleaksReport *[]scanner_gitleaks.GitLeaksFinding
	var trivyReport *scanner_trivy.TrivyReport

	if w.config.UseOpengrep {
		opengrepReport = w.opengrepScanner.Scan()
	}

	if w.config.UseGitLeaks {
		gitleaksReport = w.gitleaksScanner.Scan()
	}

	if w.config.UseTrivy {
		trivyReport = w.trivyScanner.Scan()
	}

	if opengrepReport != nil {
		fmt.Println("----------------------------------------------------------------")
		fmt.Print("Результат сканирования на основные уязвимости:\n")
		fmt.Print("Сканнер: opengrep\n")
		fmt.Printf("Версия opengrep: %s\n\n", opengrepReport.Version)

		if len(opengrepReport.Results) == 0 {
			fmt.Print("\x1b[32mУязвимости не найдены!\x1b[0m")
		}

		for _, result := range opengrepReport.Results {
			fmt.Printf("ID проверки: %s\n", result.CheckId)
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
		}

		fmt.Print("\n")
	}

	if gitleaksReport != nil {
		fmt.Println("----------------------------------------------------------------")
		fmt.Print("Результат сканирования на слитые секреты:\n")
		fmt.Print("Сканнер: gitleaks\n\n")

		if len(*gitleaksReport) == 0 {
			fmt.Print("\x1b[32mСекреты не найдены!\x1b[0m")
		}

		for _, result := range *gitleaksReport {
			fmt.Printf("Уязвимость: %s\n", result.Finding)
			fmt.Printf("Проверенный файл: %s\n", result.File)
			fmt.Printf("Коммит: %s\n", result.Commit)
			fmt.Printf("Автор коммита: %s\n", result.Author)
			fmt.Printf("Почта автора: %s\n", result.Email)
		}

		fmt.Print("\n")
	}

	if trivyReport != nil {
		fmt.Println("----------------------------------------------------------------")
		fmt.Print("Результат сканирования на CVE:\n")
		fmt.Print("Сканнер: trivy\n\n")

		for _, result := range trivyReport.Results {
			fmt.Printf("Файл: %s\n", result.Target)

			if len(result.Vulnerabilities) == 0 {
				fmt.Print("\x1b[32mУязвимости не найдены!\x1b[0m")
			}

			for idx, vuln := range result.Vulnerabilities {
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
			}
		}

		fmt.Print("\n")
	}
}
