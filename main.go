package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"log/syslog"
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

// Approved registry constant to check against
const approvedRegistry = "nexus.example..."

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
	dirPtr := flag.String("dir", ".", "Directory containing OSV JSON results and Dockerfiles")
	csvPtr := flag.Bool("csv", false, "Output results to osv_results.csv")
	verbosePtr := flag.Bool("verbose", false, "Include UNKNOWN severity results")
	syslogPtr := flag.String("syslog", "", "Syslog server URL:port combo (e.g., localhost:514)")
	flag.Parse()

	var allFindings []Finding

	// --- 1. Scan for OSV Scanner JSON Results ---
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
		fmt.Printf("Error scanning JSON results: %v\n", err)
		os.Exit(1)
	}

	// --- 2. Scan for Dockerfiles and Validate Registry ---
	err = filepath.Walk(*dirPtr, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		// Match "Dockerfile" or files named "Dockerfile.local", "Dockerfile.prod", etc.
		filename := strings.ToLower(info.Name())
		if filename == "dockerfile" || strings.HasPrefix(filename, "dockerfile.") {

			hasApprovedRegistry, err := checkDockerfileForRegistry(path, approvedRegistry)
			if err != nil {
				// Log the read error but don't halt the entire execution
				fmt.Printf("Warning: Failed to read %s: %v\n", path, err)
				return nil
			}

			if !hasApprovedRegistry {
				allFindings = append(allFindings, Finding{
					ID:       "UNAPPROVED-BASE-IMAGE",
					Severity: "HIGH",
					Package:  "base-image",
					Source:   path,
					Weight:   severityWeights["HIGH"],
				})
			}
		}
		return nil
	})
	if err != nil {
		fmt.Printf("Error scanning Dockerfiles: %v\n", err)
		os.Exit(1)
	}

	// --- 3. Sort & Output ---
	// Sort: Severity (Weight) Descending, then Package Name Ascending
	sort.Slice(allFindings, func(i, j int) bool {
		if allFindings[i].Weight != allFindings[j].Weight {
			return allFindings[i].Weight > allFindings[j].Weight
		}
		return allFindings[i].Package < allFindings[j].Package
	})

	// Trigger Syslog output if flag is provided and non-empty
	if *syslogPtr != "" {
		sendToSyslog(allFindings, *syslogPtr)
	}

	if *csvPtr {
		writeCSV(allFindings)
	} else {
		printTable(allFindings)
	}
}

func checkDockerfileForRegistry(path, registry string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()

	var fromLines []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Collect all FROM lines in order
		if strings.HasPrefix(strings.ToUpper(trimmed), "FROM") {
			fromLines = append(fromLines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return false, err
	}

	// If no FROM lines were found at all, it's a malformed or empty Dockerfile
	if len(fromLines) == 0 {
		return false, nil
	}

	finalStage := fromLines[len(fromLines)-1]
	if strings.Contains(finalStage, registry) {
		return true, nil
	}

	// If the final stage didn't match, we fail the check.
	return false, nil
}

func printTable(findings []Finding) {
	fmt.Printf("%-10s | %-22s | %-30s | %s\n", "SEVERITY", "ID", "PACKAGE", "SOURCE")
	fmt.Println(strings.Repeat("-", 110))
	for _, f := range findings {
		fmt.Printf("%-10s | %-22s | %-30s | %s\n", f.Severity, f.ID, f.Package, f.Source)
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

	writer.Write([]string{"Severity", "ID", "Package", "Source"})

	for _, f := range findings {
		writer.Write([]string{f.Severity, f.ID, f.Package, f.Source})
	}
	fmt.Println("Results successfully written to osv_results.csv")
}

func sendToSyslog(findings []Finding, addr string) {
	writer, err := syslog.Dial("udp", addr, syslog.LOG_INFO|syslog.LOG_LOCAL0, "sadom-vuln-scanner")
	if err != nil {
		fmt.Printf("Failed to connect to syslog server: %v\n", err)
		return
	}
	defer writer.Close()

	for _, f := range findings {
		msg := fmt.Sprintf("Severity: %s | ID: %s | Package: %s | Source: %s", f.Severity, f.ID, f.Package, f.Source)

		switch f.Severity {
		case "CRITICAL":
			writer.Crit(msg)
		case "HIGH":
			writer.Err(msg)
		case "MODERATE", "MEDIUM":
			writer.Warning(msg)
		case "LOW":
			writer.Info(msg)
		default:
			writer.Notice(msg)
		}
	}
	fmt.Printf("Successfully forwarded %d findings to syslog at %s\n", len(findings), addr)
}
