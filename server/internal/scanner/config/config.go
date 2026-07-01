package scanner_config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	scanner_errors "github.com/NikitaKovalenko111/codesana/internal/scanner/errors"
)

type SConfig struct {
	SecretKey   string `json:"SecretKey"`
	UseOpengrep bool   `json:"UseOpengrep"`
	UseTrivy    bool   `json:"UseTrivy"`
	UseGitLeaks bool   `json:"UseGitLeaks"`
	//HooksConfig HooksConfig `json:"Hooks"`
}

/*type HooksConfig struct {
	BlockBelow string `json:"BlockBelow"`
}*/

func Init(key string, useOpengrep bool, useTrivy bool, useGitLeaks bool) *SConfig {
	return &SConfig{
		SecretKey:   key,
		UseOpengrep: useOpengrep,
		UseTrivy:    useTrivy,
		UseGitLeaks: useGitLeaks,
	}
}

func Parse(wd string) *SConfig {
	if wd == "" {
		return nil
	}

	var cfg SConfig

	data, err := os.ReadFile(filepath.Join(wd, "config.json"))

	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}

		scanner_errors.Fatal("Не удалось прочитать config.json", err, "Запустите codesana init заново")
	}

	err = json.Unmarshal(data, &cfg)

	if err != nil {
		scanner_errors.Fatal("Некорректный config.json", err, "Проверьте структуру файла .codesana/config.json")
	}

	return &cfg
}
