package scanner_parser

import (
	"os"
	"strings"
)

type CommandFlag struct {
	FlagName string
	FlagVal  string
}

type Command struct {
	Action           string
	Flags            []CommandFlag
	Subject          string
	WorkingDirectory string
}

func Parse() *Command {
	var action, subject string
	flagsStr := make([]string, 0)
	flags := make([]CommandFlag, 0)

	if len(os.Args) > 1 {
		action = os.Args[1]

		if len(os.Args) > 2 && !strings.Contains(os.Args[2], "--") {
			subject = os.Args[2]
			flagsStr = os.Args[3:]
		} else {
			flagsStr = os.Args[2:]
		}
	}

	i := 0
	for i < len(flagsStr) {
		switch flagsStr[i] {
		case "--reason", "--report":
			if !(i+1 < len(flagsStr)) {
				panic("wrong command")
			}

			flags = append(flags, CommandFlag{
				FlagName: flagsStr[i],
				FlagVal:  flagsStr[i+1],
			})

			i += 1
		default:
			flags = append(flags, CommandFlag{
				FlagName: flagsStr[i],
				FlagVal:  "",
			})
		}

		i += 1
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
