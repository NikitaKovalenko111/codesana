package scanner_parser

import "os"

type Command struct {
	Action           string
	Flags            []string
	Subject          string
	WorkingDirectory string
}

func Parse() *Command {
	action := os.Args[1]
	subject := os.Args[2]
	flags := os.Args[3:]

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
