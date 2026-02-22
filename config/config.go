package config

import (
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// ─── struct ───────────────────────────────────────────────────────────────────

// Config holds all runtime configuration for goscout.
type Config struct {
	Rate        int           `yaml:"rate"`
	Timeout     time.Duration `yaml:"timeout"`
	Concurrency int           `yaml:"concurrency"`
	Retries     int           `yaml:"retries"`
	Top         int           `yaml:"top"`
	NoSYN       bool          `yaml:"no_syn"`
	Banner      bool          `yaml:"banner"`
	RDNS        bool          `yaml:"rdns"`
	Output      string        `yaml:"output"`
}

// ─── defaults ─────────────────────────────────────────────────────────────────

// Default returns a Config populated with sensible defaults.
func Default() Config {
	return Config{
		Rate:        500,
		Timeout:     800 * time.Millisecond,
		Concurrency: 1000,
		Retries:     1,
		Top:         1000,
		NoSYN:       false,
		Banner:      false,
		RDNS:        false,
		Output:      "human",
	}
}

// ─── load ─────────────────────────────────────────────────────────────────────

// Load reads a YAML config file and merges it onto the defaults.
// If the file does not exist, defaults are returned without error.
func Load(path string) (Config, error) {
	cfg := Default()

	// fall back to default location if path is empty
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return cfg, nil
		}
		path = filepath.Join(home, ".goscout.yaml")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil // no file — not an error
		}
		return cfg, err
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}

	return cfg, nil
}
