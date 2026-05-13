package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type OSVScannerOutput struct {
	Results []Result `json:"results"`
}

type Result struct {
	Source   Source    `json:"source"`
	Packages []Package `json:"packages"`
}

type Source struct {
	Path string `json:"path"`
}

type Package struct {
	PackageInfo PackageInfo     `json:"package"`
	Vulns       []Vulnerability `json:"vulnerabilities"`
}

type PackageInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Vulnerability struct {
	ID               string                 `json:"id"`
	DatabaseSpecific map[string]interface{} `json:"database_specific"`
}

type Finding struct {
	ID       string
	Severity string
	Package  string
	Source   string
	Weight   int
}

var severityWeights = map[string]int{
	"CRITICAL": 4,
	"HIGH":     3,
	"MODERATE": 2,
	"MEDIUM":   2,
	"LOW":      1,
	"UNKNOWN":  0,
}

func getSeverity(v Vulnerability) string {
	if v.DatabaseSpecific != nil {
		if s, ok := v.DatabaseSpecific["severity"].(string); ok {
			return strings.ToUpper(s)
		}
	}
	return "UNKNOWN"
}

func main() {
	// Define Flags
	dirPtr := flag.String("dir", ".", "Directory containing OSV JSON results")
	csvPtr := flag.Bool("csv", false, "Output results to osv_results.csv")
	verbosePtr := flag.Bool("verbose", false, "Include UNKNOWN severity results")
	flag.Parse()

	var allFindings []Finding

	err := filepath.Walk(*dirPtr, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(info.Name(), ".json") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		var output OSVScannerOutput
		if err := json.Unmarshal(data, &output); err != nil {
			return nil
		}

		for _, res := range output.Results {
			for _, pkg := range res.Packages {
				for _, v := range pkg.Vulns {
					sev := getSeverity(v)

					// Filter out UNKNOWN unless verbose is passed
					if sev == "UNKNOWN" && !*verbosePtr {
						continue
					}

					allFindings = append(allFindings, Finding{
						ID:       v.ID,
						Severity: sev,
						Package:  fmt.Sprintf("%s@%s", pkg.PackageInfo.Name, pkg.PackageInfo.Version),
						Source:   res.Source.Path,
						Weight:   severityWeights[sev],
					})
				}
			}
		}
		return nil
	})

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	// Sort: Severity (Weight) Descending, then Package Name Ascending
	sort.Slice(allFindings, func(i, j int) bool {
		if allFindings[i].Weight != allFindings[j].Weight {
			return allFindings[i].Weight > allFindings[j].Weight
		}
		return allFindings[i].Package < allFindings[j].Package
	})

	if *csvPtr {
		writeCSV(allFindings)
	} else {
		printTable(allFindings)
	}
}

func printTable(findings []Finding) {
	fmt.Printf("%-10s | %-18s | %-30s | %s\n", "SEVERITY", "ID", "PACKAGE", "SOURCE")
	fmt.Println(strings.Repeat("-", 100))
	for _, f := range findings {
		fmt.Printf("%-10s | %-18s | %-30s | %s\n", f.Severity, f.ID, f.Package, f.Source)
	}
}

func writeCSV(findings []Finding) {
	file, err := os.Create("osv_results.csv")
	if err != nil {
		fmt.Printf("Failed to create CSV: %v\n", err)
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Header
	writer.Write([]string{"Severity", "ID", "Package", "Source"})

	for _, f := range findings {
		writer.Write([]string{f.Severity, f.ID, f.Package, f.Source})
	}
	fmt.Println("Results successfully written to osv_results.csv")
}
