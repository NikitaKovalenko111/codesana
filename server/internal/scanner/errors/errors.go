package scanner_errors

import (
	stdErrors "errors"
	"fmt"
	"os"

	"github.com/fatih/color"
)

var (
	ErrWrongCommand = stdErrors.New("wrong command")
)

func Fatal(title string, err error, hint string) {
	printError(title, err, hint)
	os.Exit(1)
}

func Print(title string, err error, hint string) {
	printError(title, err, hint)
}

func PrintPlain(title string, message string, hint string) {
	fmt.Println()
	fmt.Println(color.RedString("%s", title))
	if message != "" {
		fmt.Printf("%s\n", message)
	}
	if hint != "" {
		fmt.Printf("Подсказка: %s\n", hint)
	}
	fmt.Println()
}

func PrintInitRequired() {
	PrintPlain("Проект не инициализирован", "Создайте конфиг командой codesana init", "После инициализации появится папка .codesana")
}

func PrintUnknownCommand(command string) {
	PrintPlain("Неизвестная команда", fmt.Sprintf("Команда: %s", command), "Введите codesana help all")
}

func printError(title string, err error, hint string) {
	fmt.Println()
	fmt.Println(color.RedString("%s", title))
	if err != nil {
		fmt.Printf("Причина: %v\n", err)
	}
	if hint != "" {
		fmt.Printf("Подсказка: %s\n", hint)
	}
	fmt.Println()
}
