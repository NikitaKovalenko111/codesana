package scanner_help

import (
	"fmt"

	scanner_parser "github.com/NikitaKovalenko111/codesana/internal/scanner/cli/parser"
	"github.com/fatih/color"
)

type HelpWorker struct {
	commands Commands
}

type CommandSubject struct {
	Subject string
	Desc    string
	Usecase string
}

type CommandFlag struct {
	Flag    string
	Desc    string
	Usecase string
}

type CommandManual struct {
	Action   string
	Desc     string
	Usecase  string
	Subjects []CommandSubject
	Flags    []CommandFlag
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
				Flags: []CommandFlag{
					{
						Flag:    "--diff",
						Desc:    "Проводит сканирование для git diff (изменения в коммите)",
						Usecase: "codesana scan --diff",
					},
					{
						Flag:    "--report",
						Desc:    "Создает отчет в папке .codesana/reports",
						Usecase: "codesana scan <path> --report <format>",
					},
				},
			},
			"ignore": {
				Action:  "ignore",
				Desc:    "Добавляет уязвимость в игнор",
				Usecase: "codesana ignore <hash>",
				Flags: []CommandFlag{
					{
						Flag:    "--reason",
						Desc:    "Позволяет добавить сообщение к игнору",
						Usecase: "codesana ignore <hash> --reason <message>",
					},
				},
			},
			"hooks": {
				Action:  "hooks",
				Desc:    "Создает git хук - pre-commit",
				Usecase: "codesana hooks <action>",
				Subjects: []CommandSubject{
					{
						Subject: "install",
						Desc:    "Добавляет хук",
						Usecase: "codesana hooks install",
					},
					{
						Subject: "remove",
						Desc:    "Удаляет хук",
						Usecase: "codesana hooks remove",
					},
				},
			},
			"help": {
				Action:  "help",
				Desc:    "Выводит мануал по командам",
				Usecase: "codesana help <command>",
				Subjects: []CommandSubject{
					{
						Subject: "all",
						Desc:    "Выводит все команды",
						Usecase: "codesana help all",
					},
				},
			},
		},
	}
}

func (w *HelpWorker) Run(cmd *scanner_parser.Command) {
	if cmd.Subject == "all" {
		printHeader("📖 Доступные команды Codesana")

		for _, val := range w.commands {
			printCommand(val)
		}
	} else {
		cmdManual, ok := w.commands[cmd.Subject]
		if !ok {
			fmt.Printf("\n❌ Неизвестная команда: %s\n\n", cmd.Subject)
			return
		}

		printHeader("📌 Мануал команды")
		printCommand(cmdManual)
	}
}

func printCommand(c CommandManual) {
	fmt.Printf("%s %s\n", color.CyanString(c.Action), color.YellowString("(command)"))
	fmt.Printf("  %s %s\n", color.GreenString("Описание:"), c.Desc)
	fmt.Printf("  %s %s\n", color.GreenString("Использование:"), c.Usecase)
	if len(c.Flags) > 0 {
		fmt.Printf("  %s\n", color.GreenString("Флаги:"))

		for _, f := range c.Flags {
			fmt.Printf("    %s\n", color.CyanString(f.Flag))
			fmt.Printf("      - Описание: %s\n", f.Desc)
			fmt.Printf("      - Использование: %s\n", f.Usecase)
		}
	}
	if len(c.Subjects) > 0 {
		fmt.Printf("  %s\n", color.GreenString("Действия:"))

		for _, s := range c.Subjects {
			fmt.Printf("    %s\n", color.CyanString(s.Subject))
			fmt.Printf("      - Описание: %s\n", s.Desc)
			fmt.Printf("      - Использование: %s\n", s.Usecase)
		}
	}
	fmt.Println()
	fmt.Println("──────────────────────────────────────────────")
	fmt.Println()
}

func printHeader(title string) {
	fmt.Println()
	fmt.Println("══════════════════════════════════════════════")
	fmt.Println(color.New(color.Bold).Sprint(title))
	fmt.Println("══════════════════════════════════════════════")
	fmt.Println()
}
