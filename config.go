package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type Config struct {
	WiresharkPath string `json:"wireshark_path"`
	AnthemPath    string `json:"anthem_path"`
	CapturePath   string `json:"capture_path"`
	Interface     string `json:"interface"`
}

const configFile = "network_capture_config.json"

func LoadConfig() Config {
	config := Config{}
	data, err := os.ReadFile(configFile)
	if err != nil {
		return config
	}
	json.Unmarshal(data, &config)
	return config
}

func SaveConfig(config Config) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configFile, data, 0644)
}

func GetDefaultCaptureDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, "Desktop", "AnthemNetworkCaptures")
}
