package output

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
)

// ─── csv ──────────────────────────────────────────────────────────────────────

var csvHeader = []string{"port", "state", "service", "banner", "rdns", "cve_link"}

func PrintCSV(ports []JSONPort, rdns string) error {
	w := csv.NewWriter(os.Stdout)
	defer w.Flush()

	if err := w.Write(csvHeader); err != nil {
		return err
	}

	for _, p := range ports {
		row := []string{
			strconv.Itoa(p.Port),
			p.State,
			p.Service,
			p.Banner,
			rdns,
			p.CVELink,
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	return nil
}

func WriteCSV(path string, ports []JSONPort, rdns string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("cannot create file: %s", path)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if err := w.Write(csvHeader); err != nil {
		return err
	}

	for _, p := range ports {
		row := []string{
			strconv.Itoa(p.Port),
			p.State,
			p.Service,
			p.Banner,
			rdns,
			p.CVELink,
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	return nil
}
