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
		opengrepReport = w.opengrepScanner.Scan(files, w.command.Subject)
	}

	if w.config.UseGitLeaks {
		gitleaksReport = w.gitleaksScanner.Scan(files, w.command.Subject)
	}

	if w.config.UseTrivy {
		trivyReport = w.trivyScanner.Scan(files, w.command.Subject)
	}

	if opengrepReport != nil {
		printSection(
			"Результат сканирования на основные уязвимости",
			"OpenGrep",
		)

		fmt.Printf("Версия: %s\n\n", opengrepReport.Version)

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

			printSeparator()

			fmt.Printf("[%s] %s\n",
				severityColor(result.Extra.Severity),
				result.CheckId,
			)

			fmt.Printf("Хеш: %s\n", vulnHashString)
			fmt.Printf("Файл: %s\n", result.Path)

			fmt.Printf("\nСообщение:\n%s\n",
				result.Extra.Message,
			)

			if result.Extra.Fix != "" {
				fmt.Printf("\nПредложенное исправление:\n%s\n",
					result.Extra.Fix,
				)
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

		fmt.Printf(
			"\nВсего: %d найдено\n",
			unignoredCount,
		)

		if unignoredCount == 0 {
			fmt.Print("\x1b[32mУязвимости не найдены!\x1b[0m")
		}

		fmt.Print("\n")
	}

	if gitleaksReport != nil {
		printSection(
			"Результат сканирования на слитые секреты",
			"GitLeaks",
		)

		var unignoredCount int = 0

		for _, result := range *gitleaksReport {
			hashData := hashData{
				FactorF: result.RuleID,
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

			printSeparator()

			fmt.Printf("[SECRET] %s\n\n", result.Match)

			fmt.Printf("Правило: %s\n", result.RuleID)
			fmt.Printf("Хеш: %s\n", vulnHashString)
			fmt.Printf("Файл: %s\n", result.File)
			fmt.Printf("Описание: %s\n", result.Desc)

			unignoredCount += 1
		}

		fmt.Printf(
			"\nВсего: %d секретов найдено\n",
			unignoredCount,
		)

		if unignoredCount == 0 {
			fmt.Print("\x1b[32mСекреты не найдены!\x1b[0m")
		}

		fmt.Print("\n")
	}

	if trivyReport != nil {
		printSection(
			"Результат сканирования зависимостей",
			"Trivy",
		)

		for _, result := range trivyReport.Results {
			fmt.Printf("Файл: %s\n", result.Target)

			var unignoredCount int = 0

			for _, vuln := range result.Vulnerabilities {
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

				printSeparator()

				fmt.Printf(
					"[%s] %s\n",
					severityColor(vuln.Severity),
					vuln.VulnerabilityID,
				)

				fmt.Printf("Хеш: %s\n", vulnHashString)
				fmt.Printf("Пакет: %s\n", vuln.PkgName)
				fmt.Printf("Установлено: %s\n", vuln.InstalledVersion)
				fmt.Printf("Исправлено: %s\n", vuln.FixedVersion)

				if vuln.Title != "" {
					fmt.Printf("\nНазвание:\n%s\n", vuln.Title)
				}

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

		fmt.Println()
		fmt.Println("════════════════════════════════════════════════════════════")
		fmt.Println("Codesana Scan Summary")
		fmt.Println("════════════════════════════════════════════════════════════")

		if vulns > 0 {
			fmt.Printf(
				"\n❌ Found %d blocking vulnerabilities\n",
				vulns,
			)

			os.Exit(1)
		}

		fmt.Println("\n✅ No blocking vulnerabilities found")
		os.Exit(0)
	}
}

func printSection(title, scanner string) {
	fmt.Println()
	fmt.Println("════════════════════════════════════════════════════════════")
	fmt.Printf("🔍 %s\n", title)
	fmt.Printf("Scanner: %s\n", scanner)
	fmt.Println("════════════════════════════════════════════════════════════")
}

func severityColor(severity string) string {
	switch severity {
	case "CRITICAL", "HIGH", "ERROR":
		return "\033[31m" + severity + "\033[0m"
	case "MEDIUM", "WARNING":
		return "\033[33m" + severity + "\033[0m"
	case "LOW", "INFO", "UNKNOWN":
		return "\033[34m" + severity + "\033[0m"
	default:
		return severity
	}
}

func printSeparator() {
	fmt.Println("────────────────────────────────────────────────────────────")
}
