package scanner_scan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	scanner_parser "github.com/NikitaKovalenko111/codesana/internal/scanner/cli/parser"
	scanner_config "github.com/NikitaKovalenko111/codesana/internal/scanner/config"
	scanner_gitleaks "github.com/NikitaKovalenko111/codesana/internal/scanner/tools/gitleaks"
	scanner_opengrep "github.com/NikitaKovalenko111/codesana/internal/scanner/tools/opengrep"
	scanner_trivy "github.com/NikitaKovalenko111/codesana/internal/scanner/tools/trivy"
	scanner_ignore "github.com/NikitaKovalenko111/codesana/internal/scanner/workers/ignore"
	"github.com/phpdave11/gofpdf"
)

type ScanWorker struct {
	command         *scanner_parser.Command
	codesanawd      string
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
	codesanawd string,
) *ScanWorker {
	return &ScanWorker{
		command:         cmd,
		config:          cfg,
		opengrepScanner: opengrep,
		gitleaksScanner: gitleaks,
		trivyScanner:    trivy,
		ignoreMap:       ignoreMap,
		codesanawd:      codesanawd,
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
	}

	var hasReportFlag bool = false
	var reportFlag *scanner_parser.CommandFlag

	for _, f := range w.command.Flags {
		if f.FlagName == "--report" {
			hasReportFlag = true
			reportFlag = &f
			break
		}
	}

	if hasReportFlag && reportFlag.FlagVal == "pdf" {
		err := os.MkdirAll(filepath.Join(w.codesanawd, "reports"), 0755)
		if err != nil {
			panic(err)
		}

		err = w.makePDFReport(opengrepReport, gitleaksReport, trivyReport)
		if err != nil {
			panic(err)
		}
	}

	fmt.Println()
	fmt.Println("════════════════════════════════════════════════════════════")
	fmt.Println("Итог сканирования Codesana")
	fmt.Println("════════════════════════════════════════════════════════════")

	if vulns > 0 {
		fmt.Printf(
			"\n❌ Найдено %d критичных уязвимостей\n",
			vulns,
		)

		os.Exit(1)
	}

	fmt.Println("\n✅ Критичных уязвимостей не найдено")
	os.Exit(0)
}

func (w *ScanWorker) makePDFReport(
	opengrepRes *scanner_opengrep.OpengrepScanResults,
	gitleaksRes *[]scanner_gitleaks.GitLeaksFinding,
	trivyRes *scanner_trivy.TrivyReport,
) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(15, 15, 15)
	pdf.SetAutoPageBreak(true, 15)

	pdf.AddPage()

	pdf.SetFont("Arial", "B", 24)
	pdf.Cell(0, 15, "Codesana Security Report")
	pdf.Ln(20)

	pdf.SetFont("Arial", "", 12)

	pdf.Cell(50, 8, "Generated:")
	pdf.Cell(0, 8, time.Now().Format(time.RFC3339))
	pdf.Ln(8)

	var critical int
	var high int
	var medium int
	var low int

	if opengrepRes != nil {
		for _, r := range opengrepRes.Results {
			switch r.Extra.Severity {
			case "ERROR":
				high++
			case "WARNING":
				medium++
			case "INFO":
				low++
			}
		}
	}

	if trivyRes != nil {
		for _, r := range trivyRes.Results {
			for _, v := range r.Vulnerabilities {
				switch v.Severity {
				case "CRITICAL":
					critical++
				case "HIGH":
					high++
				case "MEDIUM":
					medium++
				default:
					low++
				}
			}
		}
	}

	if gitleaksRes != nil {
		high += len(*gitleaksRes)
	}

	pdf.Ln(10)

	pdf.SetFont("Arial", "B", 18)
	pdf.Cell(0, 10, "Summary")
	pdf.Ln(13)

	addSummaryTable(
		pdf,
		critical,
		high,
		medium,
		low,
		0,
	)

	if len(opengrepRes.Results) > 0 {
		pdf.AddPage()

		pdf.SetFont("Arial", "B", 18)
		pdf.Cell(0, 10, "OpenGrep Findings")
		pdf.Ln(15)

		addOpenGrepTable(pdf, opengrepRes.Results)

		pdf.Ln(10)

		pdf.SetFont("Arial", "B", 14)
		pdf.Cell(0, 8, "Detailed Findings")
		pdf.Ln(12)

		for i, r := range opengrepRes.Results {
			severityReportColor(pdf, r.Extra.Severity)

			pdf.SetFont("Arial", "B", 12)
			pdf.Cell(
				0,
				8,
				fmt.Sprintf(
					"[%s] Finding #%d",
					r.Extra.Severity,
					i+1,
				),
			)

			pdf.SetTextColor(0, 0, 0)
			pdf.Ln(8)

			pdf.SetFont("Arial", "", 11)

			var fix string
			if r.Extra.Fix == "" {
				fix = "None"
			}

			pdf.MultiCell(0, 6,
				fmt.Sprintf(
					`Rule: %s

File: %s

Severity: %s

Line: %d

Message:
%s

Fix:
%s`,
					r.CheckId,
					r.Path,
					r.Extra.Severity,
					r.Start.Line,
					r.Extra.Message,
					fix,
				),
				"",
				"",
				false,
			)

			pdf.Ln(4)
		}
	}

	if len(*gitleaksRes) > 0 {
		pdf.AddPage()

		pdf.SetFont("Arial", "B", 18)
		pdf.Cell(0, 10, "GitLeaks Findings")
		pdf.Ln(15)

		headers := []string{
			"Rule",
			"File",
		}

		widths := []float64{
			60,
			110,
		}

		pdf.SetFont("Arial", "B", 10)

		for i, h := range headers {
			pdf.CellFormat(
				widths[i],
				8,
				h,
				"1",
				0,
				"C",
				false,
				0,
				"",
			)
		}

		pdf.Ln(-1)

		pdf.SetFont("Arial", "", 9)

		for _, r := range *gitleaksRes {
			pdf.CellFormat(widths[0], 8, r.RuleID, "1", 0, "", false, 0, "")
			pdf.CellFormat(widths[1], 8, r.File, "1", 1, "", false, 0, "")
		}

		pdf.Ln(10)

		pdf.SetFont("Arial", "B", 14)
		pdf.Cell(0, 8, "Detailed Findings")
		pdf.Ln(12)

		for i, r := range *gitleaksRes {

			pdf.SetFont("Arial", "B", 12)
			pdf.Cell(0, 8, fmt.Sprintf("Secret #%d", i+1))
			pdf.Ln(8)

			pdf.SetFont("Arial", "", 11)

			pdf.MultiCell(
				0,
				6,
				fmt.Sprintf(
					`Rule: %s

Description:
%s

File:
%s

Match:
%s

Secret:
%s`,
					r.RuleID,
					r.Desc,
					r.File,
					r.Match,
					r.Secret,
				),
				"",
				"",
				false,
			)

			pdf.Ln(4)
		}
	}

	trivyVulns := 0

	for _, r := range trivyRes.Results {
		trivyVulns += len(r.Vulnerabilities)
	}

	if trivyVulns > 0 {
		pdf.AddPage()

		pdf.SetFont("Arial", "B", 18)
		pdf.Cell(0, 10, "Trivy Findings")
		pdf.Ln(15)

		var allVulns []scanner_trivy.TrivyReportVulnerability

		for _, result := range trivyRes.Results {
			allVulns = append(
				allVulns,
				result.Vulnerabilities...,
			)
		}

		addTrivyTable(
			pdf,
			allVulns,
		)

		pdf.Ln(10)

		pdf.SetFont("Arial", "B", 14)
		pdf.Cell(0, 8, "Detailed Findings")
		pdf.Ln(12)

		pdf.SetFont("Arial", "", 11)

		pdf.Cell(0, 6, fmt.Sprintf("Branch: %s", trivyRes.Metadata.Branch))
		pdf.Ln(6)

		pdf.Cell(0, 6, fmt.Sprintf("Commit: %s", trivyRes.Metadata.Commit))
		pdf.Ln(6)

		pdf.Cell(0, 6, fmt.Sprintf("Author: %s", trivyRes.Metadata.Author))
		pdf.Ln(12)

		for _, result := range trivyRes.Results {

			for _, vuln := range result.Vulnerabilities {

				pdf.SetFont("Arial", "B", 12)

				severityReportColor(pdf, vuln.Severity)

				pdf.Cell(
					0,
					8,
					fmt.Sprintf(
						"[%s] %s",
						vuln.Severity,
						vuln.VulnerabilityID,
					),
				)

				pdf.SetTextColor(0, 0, 0)
				pdf.Ln(8)

				pdf.SetFont("Arial", "", 11)

				pdf.MultiCell(
					0,
					6,
					fmt.Sprintf(
						`Title:
%s

Package:
%s

Installed Version:
%s

Fixed Version:
%s

Severity:
%s

Target:
%s`,
						vuln.Title,
						vuln.PkgName,
						vuln.InstalledVersion,
						vuln.FixedVersion,
						vuln.Severity,
						result.Target,
					),
					"",
					"",
					false,
				)

				pdf.Ln(4)
			}
		}
	}

	now := strconv.FormatInt(time.Now().Unix(), 10)

	return pdf.OutputFileAndClose(filepath.Join(w.codesanawd, "reports", fmt.Sprintf("report-%s.pdf", now)))
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

func severityReportColor(pdf *gofpdf.Fpdf, severity string) {
	switch severity {
	case "CRITICAL":
		pdf.SetTextColor(180, 0, 0)

	case "HIGH", "ERROR":
		pdf.SetTextColor(255, 80, 80)

	case "MEDIUM", "WARNING":
		pdf.SetTextColor(255, 180, 0)

	case "LOW":
		pdf.SetTextColor(0, 120, 255)

	default:
		pdf.SetTextColor(120, 120, 120)
	}
}

func addHeader(pdf *gofpdf.Fpdf, title string) {
	pdf.SetFont("Arial", "B", 20)
	pdf.Cell(0, 12, title)
	pdf.Ln(15)

	pdf.SetFont("Arial", "", 10)
	pdf.Cell(0, 6, time.Now().Format("2006-01-02 15:04:05"))
	pdf.Ln(10)
}

func addSummaryTable(
	pdf *gofpdf.Fpdf,
	critical, high, medium, low, info int,
) {
	headers := []string{"Severity", "Count"}
	widths := []float64{80, 40}

	pdf.SetFont("Arial", "B", 11)

	for i, h := range headers {
		pdf.CellFormat(widths[i], 8, h, "1", 0, "C", false, 0, "")
	}

	pdf.Ln(-1)

	rows := []struct {
		Severity string
		Count    int
	}{
		{"CRITICAL", critical},
		{"HIGH", high},
		{"MEDIUM", medium},
		{"LOW", low},
		{"INFO", info},
	}

	pdf.SetFont("Arial", "", 10)

	for _, row := range rows {
		severityReportColor(pdf, row.Severity)

		pdf.CellFormat(widths[0], 8, row.Severity, "1", 0, "", false, 0, "")

		pdf.SetTextColor(0, 0, 0)

		pdf.CellFormat(
			widths[1],
			8,
			strconv.Itoa(row.Count),
			"1",
			1,
			"C",
			false,
			0,
			"",
		)
	}

	pdf.Ln(10)
}

func addOpenGrepTable(
	pdf *gofpdf.Fpdf,
	results []scanner_opengrep.OpengrepScanSingleResult,
) {
	headers := []string{
		"Severity",
		"File",
		"Line",
	}

	widths := []float64{
		25,
		120,
		20,
	}

	pdf.SetFont("Arial", "B", 10)

	for i, h := range headers {
		pdf.CellFormat(widths[i], 8, h, "1", 0, "C", false, 0, "")
	}

	pdf.Ln(-1)

	pdf.SetFont("Arial", "", 9)

	for _, r := range results {

		severityReportColor(pdf, r.Extra.Severity)

		pdf.CellFormat(widths[0], 8, r.Extra.Severity, "1", 0, "", false, 0, "")

		pdf.SetTextColor(0, 0, 0)

		pdf.CellFormat(widths[1], 8, r.Path, "1", 0, "", false, 0, "")
		pdf.CellFormat(widths[2], 8, strconv.Itoa(r.Start.Line), "1", 1, "", false, 0, "")
	}
}

func addTrivyTable(
	pdf *gofpdf.Fpdf,
	vulns []scanner_trivy.TrivyReportVulnerability,
) {
	headers := []string{
		"Severity",
		"CVE",
		"Package",
		"Current",
		"Fixed",
	}

	widths := []float64{
		25,
		40,
		45,
		35,
		35,
	}

	pdf.SetFont("Arial", "B", 10)

	for i, h := range headers {
		pdf.CellFormat(widths[i], 8, h, "1", 0, "C", false, 0, "")
	}

	pdf.Ln(-1)

	pdf.SetFont("Arial", "", 9)

	for _, v := range vulns {

		severityReportColor(pdf, v.Severity)

		pdf.CellFormat(widths[0], 8, v.Severity, "1", 0, "", false, 0, "")

		pdf.SetTextColor(0, 0, 0)

		pdf.CellFormat(widths[1], 8, v.VulnerabilityID, "1", 0, "", false, 0, "")
		pdf.CellFormat(widths[2], 8, v.PkgName, "1", 0, "", false, 0, "")
		pdf.CellFormat(widths[3], 8, v.InstalledVersion, "1", 0, "", false, 0, "")
		pdf.CellFormat(widths[4], 8, v.FixedVersion, "1", 1, "", false, 0, "")
	}
}
