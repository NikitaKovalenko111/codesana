package scanner_config

type SConfig struct {
	SecretKey   string
	UseSemgrep  bool
	UseTrivy    bool
	UseGitLeaks bool
}

func Init(key string, useSemgrep bool, useTrivy bool, useGitLeaks bool) *SConfig {
	return &SConfig{
		SecretKey:   key,
		UseSemgrep:  useSemgrep,
		UseTrivy:    useTrivy,
		UseGitLeaks: useGitLeaks,
	}
}
