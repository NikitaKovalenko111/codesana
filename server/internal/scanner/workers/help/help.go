package scanner_help

import (
	"fmt"

	scanner_parser "github.com/NikitaKovalenko111/codesana/internal/scanner/cli/parser"
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

var green string = "\033[32m"
var cyan string = "\033[36m"
var yellow string = "\033[33m"
var reset string = "\033[0m"
var bold string = "\033[1m"

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
	fmt.Printf("%s%s%s %s\n", cyan, c.Action, reset, yellow+"(command)"+reset)
	fmt.Printf("  %sОписание:%s %s\n", green, reset, c.Desc)
	fmt.Printf("  %sИспользование:%s %s\n", green, reset, c.Usecase)
	if len(c.Flags) > 0 {
		fmt.Printf("  %sФлаги:%s\n", green, reset)

		for _, f := range c.Flags {
			fmt.Printf("    %s%s%s\n", cyan, f.Flag, reset)
			fmt.Printf("      - Описание: %s\n", f.Desc)
			fmt.Printf("      - Использование: %s\n", f.Usecase)
		}
	}
	if len(c.Subjects) > 0 {
		fmt.Printf("  %sДействия:%s\n", green, reset)

		for _, s := range c.Subjects {
			fmt.Printf("    %s%s%s\n", cyan, s.Subject, reset)
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
	fmt.Printf("%s%s%s\n", bold, title, reset)
	fmt.Println("══════════════════════════════════════════════")
	fmt.Println()
}
