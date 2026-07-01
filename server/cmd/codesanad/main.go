package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"

	scanner_errors "github.com/NikitaKovalenko111/codesana/internal/scanner/errors"
)

func main() {
	wd, err := os.Getwd()
	if err != nil {
		scanner_errors.Fatal("Не удалось получить рабочую директорию", err, "Запустите команду из доступной папки")
	}

	fs := http.FileServer(http.Dir(filepath.Join(wd, "./scripts")))

	http.Handle("/", fs)

	log.Println("Listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
