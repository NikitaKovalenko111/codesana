package scanner_help

import (
	"fmt"

	scanner_parser "github.com/NikitaKovalenko111/codesana/internal/scanner/cli/parser"
)

type HelpWorker struct {
	commands Commands
}

type CommandManual struct {
	Action  string
	Desc    string
	Usecase string
}

type Commands map[string]CommandManual

func Init() *HelpWorker {
	return &HelpWorker{
		commands: Commands{
			"init": {
				Action:  "init",
				Desc:    "Инициализирует проект, создает директорию и config файл",
				Usecase: "codesana init",
			},
			"update": {
				Action:  "update",
				Desc:    "Устанавливает и обновляет сканнеры в корневой директории codesana",
				Usecase: "codesana update",
			},
			"scan": {
				Action:  "scan",
				Desc:    "Сканирует данную директорию на уязвимости",
				Usecase: "codesana scan <path to directory>",
			},
		},
	}
}

func (w *HelpWorker) Run(cmd *scanner_parser.Command) {
	if cmd.Subject == "all" {
		fmt.Println("Доступные команды: ")
		fmt.Println()

		for _, val := range w.commands {
			fmt.Printf("Команда: %s\n", val.Action)
			fmt.Printf("Описание: %s\n", val.Desc)
			fmt.Printf("Пример использования: %s\n", val.Usecase)
			fmt.Println("")
		}
	} else {
		cmdManual := w.commands[cmd.Subject]

		fmt.Println()
		fmt.Printf("Команда: %s\n", cmdManual.Action)
		fmt.Printf("Описание: %s\n", cmdManual.Desc)
		fmt.Printf("Пример использования: %s\n", cmdManual.Usecase)
		fmt.Println()
	}
}
