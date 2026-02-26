package output

import (
	"encoding/json"
	"fmt"
	"os"
)

// ─── json ─────────────────────────────────────────────────────────────────────

type JSONPort struct {
	Port    int      `json:"port"`
	State   string   `json:"state"`
	Service string   `json:"service,omitempty"`
	Banner  string   `json:"banner,omitempty"`
	Tech    []string `json:"tech,omitempty"`
	CVELink string   `json:"cve_link,omitempty"`
}

type JSONResult struct {
	Target string     `json:"target"`
	IP     string     `json:"ip,omitempty"`
	RDNS   string     `json:"rdns,omitempty"`
	Ports  []JSONPort `json:"ports"`
	Meta   JSONMeta   `json:"meta"`
}

func NewJSONResult(target, ip, rdns string, ports []JSONPort, meta JSONMeta) JSONResult {
	if ports == nil {
		ports = []JSONPort{}
	}
	return JSONResult{
		Target: target,
		IP:     ip,
		RDNS:   rdns,
		Ports:  ports,
		Meta:   meta,
	}
}

type JSONMeta struct {
	Scanned  int    `json:"scanned"`
	Open     int    `json:"open"`
	Duration string `json:"duration"`
}

func PrintJSON(result JSONResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func WriteJSON(path string, result JSONResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
