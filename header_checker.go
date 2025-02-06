package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
)

// File paths (updated to read from "files/" directory)
const (
	missingHeadersFile  = "files/missing.txt"
	insecureHeadersFile = "files/insecure.txt"
	securityHeadersFile = "files/security.txt"
	fingerprintFile     = "files/fingerprint.txt"
	outputCSV           = "header_analysis.csv"
)

// Load headers from a file into a map
func loadHeaders(filename string) (map[string]bool, error) {
	headers := make(map[string]bool)
	file, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(file), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			headers[strings.ToLower(line)] = true
		}
	}

	return headers, nil
}

// Read domains from a text file
func readDomainsFromFile(filename string) ([]string, error) {
	var domains []string
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" {
			domains = append(domains, domain)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return domains, nil
}

// Analyze headers of a domain
func analyzeHeaders(domain string, missingHeaders, insecureHeaders, securityHeaders, fingerprintHeaders map[string]bool) (string, []string, []string, []string, []string) {
	url := "https://" + domain
	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Get(url)
	if err != nil {
		return domain, []string{"Failed to connect"}, []string{}, []string{}, []string{}
	}
	defer resp.Body.Close()

	foundHeaders := make(map[string]bool)
	for header := range resp.Header {
		foundHeaders[strings.ToLower(header)] = true
	}

	var missingList, insecureList, securityList, fingerprintList []string

	// Check for missing headers
	for header := range missingHeaders {
		if _, exists := foundHeaders[strings.ToLower(header)]; !exists {
			missingList = append(missingList, header)
		}
	}

	// Check for insecure headers
	for header := range resp.Header {
		if _, insecure := insecureHeaders[strings.ToLower(header)]; insecure {
			insecureList = append(insecureList, header)
		}
	}

	// Check for security headers
	for header := range resp.Header {
		if _, secure := securityHeaders[strings.ToLower(header)]; secure {
			securityList = append(securityList, header)
		}
	}

	// Check for fingerprint headers
	for header := range resp.Header {
		if _, fingerprint := fingerprintHeaders[strings.ToLower(header)]; fingerprint {
			fingerprintList = append(fingerprintList, header)
		}
	}

	return domain, missingList, insecureList, securityList, fingerprintList
}

// Display results in a color-coded terminal output
func displayResults(domain string, missing, insecure, security, fingerprint []string) {
	fmt.Println("\n🔎 Scanning:", color.CyanString(domain))

	fmt.Println("🟢 Security Headers Found:", color.GreenString(strings.Join(security, ", ")))

	if len(missing) > 0 {
		fmt.Println("🟡 Missing Headers:", color.YellowString(strings.Join(missing, ", ")))
	} else {
		fmt.Println("✅ No missing headers!")
	}

	if len(insecure) > 0 {
		fmt.Println("🔴 Insecure Headers:", color.RedString(strings.Join(insecure, ", ")))
	} else {
		fmt.Println("✅ No insecure headers detected.")
	}

	if len(fingerprint) > 0 {
		fmt.Println("🔍 Technologies Detected (Fingerprint):", color.BlueString(strings.Join(fingerprint, ", ")))
	}
}

// Save results to CSV file
func saveResultsToCSV(results [][]string) error {
	file, err := os.Create(outputCSV)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// CSV Header
	writer.Write([]string{"URL", "Missing Headers", "Insecure Headers", "Security Headers", "Fingerprint Headers"})

	// Write data rows
	for _, result := range results {
		writer.Write(result)
	}

	return nil
}

func main() {
	// Load header lists
	missingHeaders, err := loadHeaders(missingHeadersFile)
	if err != nil {
		fmt.Println(color.RedString("Error loading missing.txt: %v", err))
		return
	}

	insecureHeaders, err := loadHeaders(insecureHeadersFile)
	if err != nil {
		fmt.Println(color.RedString("Error loading insecure.txt: %v", err))
		return
	}

	securityHeaders, err := loadHeaders(securityHeadersFile)
	if err != nil {
		fmt.Println(color.RedString("Error loading security.txt: %v", err))
		return
	}

	fingerprintHeaders, err := loadHeaders(fingerprintFile)
	if err != nil {
		fmt.Println(color.RedString("Error loading fingerprint.txt: %v", err))
		return
	}

	// Ask for domain file
	fmt.Print("📄 Enter domain file name (or press ENTER for manual input): ")
	var filename string
	fmt.Scanln(&filename)

	var domains []string
	if filename != "" {
		domains, err = readDomainsFromFile(filename)
		if err != nil {
			fmt.Println(color.RedString("Error reading file: %v", err))
			return
		}
		fmt.Println(color.GreenString("✅ Loaded %d domains from file.", len(domains)))
	} else {
		// Manual input
		fmt.Print("📝 Enter domains/subdomains (space-separated): ")
		var input string
		fmt.Scanln(&input)
		domains = strings.Fields(input)
	}

	// Analyze domains
	var results [][]string
	for _, domain := range domains {
		d, missing, insecure, security, fingerprint := analyzeHeaders(domain, missingHeaders, insecureHeaders, securityHeaders, fingerprintHeaders)
		displayResults(d, missing, insecure, security, fingerprint)
		results = append(results, []string{d, strings.Join(missing, "; "), strings.Join(insecure, "; "), strings.Join(security, "; "), strings.Join(fingerprint, "; ")})
	}

	// Save results to CSV
	err = saveResultsToCSV(results)
	if err != nil {
		fmt.Println(color.RedString("Error saving CSV: %v", err))
	} else {
		fmt.Println(color.GreenString("📄 Results saved in '%s'", outputCSV))
	}
}

