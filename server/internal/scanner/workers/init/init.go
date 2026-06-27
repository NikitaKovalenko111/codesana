package scanner_init

import (
	"encoding/json"
	"fmt"
	"os"

	scanner_parser "github.com/NikitaKovalenko111/codesana/internal/scanner/cli/parser"
	scanner_config "github.com/NikitaKovalenko111/codesana/internal/scanner/config"
	"github.com/google/uuid"
)

type InitWorker struct {
	command *scanner_parser.Command
}

func Init(cmd *scanner_parser.Command) *InitWorker {
	return &InitWorker{
		command: cmd,
	}
}

func (w *InitWorker) Run() {
	fmt.Println("Создание проекта...")

	var useOpengrep bool
	var useOpengrepAns string
	fmt.Print("Использовать сканнер Opengrep? (Yes/No): ")
	fmt.Scan(&useOpengrepAns)

	if useOpengrepAns == "Yes" {
		useOpengrep = true
	} else {
		useOpengrep = false
	}

	var useTrivy bool
	var useTrivyAns string
	fmt.Print("Использовать сканнер Trivy? (Yes/No): ")
	fmt.Scan(&useTrivyAns)

	if useTrivyAns == "Yes" {
		useTrivy = true
	} else {
		useTrivy = false
	}

	var useGitLeaks bool
	var useGitLeaksAns string
	fmt.Print("Использовать сканнер GitLeaks? (Yes/No): ")
	fmt.Scan(&useGitLeaksAns)

	if useGitLeaksAns == "Yes" {
		useGitLeaks = true
	} else {
		useGitLeaks = false
	}

	secretKey := uuid.New()

	cfg := scanner_config.Init(secretKey.String(), useOpengrep, useTrivy, useGitLeaks)

	dirPath := w.command.WorkingDirectory + "/.codesana"
	fileName := "config.json"

	if err := os.MkdirAll(dirPath, 0o755); err != nil {
		panic("couldn't create project dir")
	}

	f, err := os.Create(dirPath + "/" + fileName)

	if err != nil {
		panic("couldn't create config file")
	}

	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")

	if err := enc.Encode(cfg); err != nil {
		panic("couldn't write config")
	}

	fmt.Println("Проект успешно создан!")
	fmt.Printf("Ваш СЕКРЕТНЫЙ ключ: %s", secretKey.String())
}
