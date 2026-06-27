package scanner_parser

import (
	"os"
	"strings"
)

type Command struct {
	Action           string
	Flags            []string
	Subject          string
	WorkingDirectory string
}

func Parse() *Command {
	var action, subject string
	flags := make([]string, 10)

	if len(os.Args) > 1 {
		action = os.Args[1]

		if len(os.Args) > 2 && !strings.Contains(os.Args[2], "--") {
			subject = os.Args[2]
			flags = os.Args[3:]
		} else {
			flags = os.Args[2:]
		}
	}

	wd, err := os.Getwd()

	if err != nil {
		panic("couldn't get current working directory")
	}

	return &Command{
		Action:           action,
		Flags:            flags,
		Subject:          subject,
		WorkingDirectory: wd,
	}
}
