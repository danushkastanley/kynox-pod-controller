package classifier

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	pb "pod-controller/pkg/telemetry"

	"github.com/sirupsen/logrus"
)

// CVEClassifier implements CVE-based security event classification
type CVEClassifier struct {
	mu sync.RWMutex

	// Configuration
	dataPath       string
	apiKey         string
	apiEndpoint    string
	updateInterval time.Duration

	// CVE database
	cveDatabase map[string]*CVEEntry
	lastUpdate  time.Time

	// Fallback classifier
	fallbackClassifier EventClassifierInterface
	threatDetector     ThreatDetectorInterface

	// Metrics
	classifications int64
	cveMatches      int64
	apiCalls        int64
}

// CVEEntry represents a CVE record
type CVEEntry struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	CVSS        float64  `json:"cvss"`
	Severity    string   `json:"severity"`
	References  []string `json:"references"`
	Keywords    []string `json:"keywords"`
	Published   string   `json:"published"`
	Modified    string   `json:"modified"`
}

// NVDResponse represents the NIST NVD API response structure
type NVDResponse struct {
	Results []struct {
		CVE struct {
			ID           string `json:"id"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Published string `json:"published"`
			Modified  string `json:"lastModified"`
			Metrics   struct {
				CVSSMetricV31 []struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
	TotalResults int `json:"totalResults"`
}

// NewCVEClassifier creates a new CVE-based classifier
func NewCVEClassifier(config *ClassifierConfig) (*CVEClassifier, error) {
	logrus.WithFields(logrus.Fields{
		"data_path":       config.CVEDataPath,
		"api_endpoint":    config.CVEAPIEndpoint,
		"update_interval": config.CVEUpdateInterval,
	}).Info("Initializing CVE classifier")

	// Create fallback classifier
	fallback := NewEventClassifier(config.ThreatDetector)

	// Validate update interval - ensure it's positive to avoid ticker panic
	updateInterval := config.CVEUpdateInterval
	if updateInterval <= 0 {
		updateInterval = 24 * time.Hour // Default to 24 hours
		logrus.WithField("default_interval", updateInterval).Warn("Invalid update interval, using default")
	}

	classifier := &CVEClassifier{
		dataPath:           config.CVEDataPath,
		apiKey:             config.CVEAPIKey,
		apiEndpoint:        config.CVEAPIEndpoint,
		updateInterval:     updateInterval,
		cveDatabase:        make(map[string]*CVEEntry),
		fallbackClassifier: fallback,
		threatDetector:     config.ThreatDetector,
	}

	// Load existing CVE data
	if err := classifier.loadCVEData(); err != nil {
		logrus.WithError(err).Warn("Failed to load existing CVE data, will fetch fresh data")
	}

	// Start background updater only if we have a valid API endpoint
	if config.CVEAPIEndpoint != "" {
		go classifier.startUpdateRoutine()
	} else {
		logrus.Info("No CVE API endpoint configured, skipping background updates")
	}

	return classifier, nil
}

// ClassifyEvent implements the EventClassifierInterface
func (c *CVEClassifier) ClassifyEvent(event *pb.SecurityEvent) (Severity, string) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	c.classifications++

	// First, try CVE-based classification
	if severity, description := c.classifyWithCVE(event); severity != "" {
		c.cveMatches++
		logrus.WithFields(logrus.Fields{
			"event_type": event.GetEventType(),
			"cve_match":  true,
			"severity":   severity,
		}).Debug("CVE classification successful")
		return severity, description
	}

	// Fallback to default classifier
	logrus.WithField("event_type", event.GetEventType()).Debug("No CVE match, using fallback classifier")
	return c.fallbackClassifier.ClassifyEvent(event)
}

// classifyWithCVE performs CVE-based classification
func (c *CVEClassifier) classifyWithCVE(event *pb.SecurityEvent) (Severity, string) {
	// Extract potential CVE indicators from the event
	indicators := c.extractCVEIndicators(event)

	// Check for direct CVE matches
	for _, indicator := range indicators {
		if cveEntry, exists := c.cveDatabase[indicator]; exists {
			return c.createClassificationFromCVE(event, cveEntry)
		}
	}

	// Check for keyword matches in CVE descriptions
	return c.classifyByKeywords(event, indicators)
}

// extractCVEIndicators extracts potential CVE identifiers and keywords from the event
func (c *CVEClassifier) extractCVEIndicators(event *pb.SecurityEvent) []string {
	var indicators []string

	// Collect text from various event fields
	var textFields []string
	if command := event.GetCommand(); command != "" {
		textFields = append(textFields, command)
	}
	if filePath := event.GetFilePath(); filePath != "" {
		textFields = append(textFields, filePath)
	}
	if destIP := event.GetDestinationIp(); destIP != "" {
		textFields = append(textFields, destIP)
	}
	if srcIP := event.GetSourceIp(); srcIP != "" {
		textFields = append(textFields, srcIP)
	}

	// Extract CVE patterns and keywords
	for _, text := range textFields {
		if text != "" {
			// Look for CVE-YYYY-NNNN patterns
			patterns := c.extractCVEPatterns(text)
			indicators = append(indicators, patterns...)

			// Extract security-relevant keywords
			keywords := c.extractSecurityKeywords(text)
			indicators = append(indicators, keywords...)
		}
	}

	logrus.WithFields(logrus.Fields{
		"event_type":  event.GetEventType(),
		"command":     event.GetCommand(),
		"file_path":   event.GetFilePath(),
		"text_fields": textFields,
		"indicators":  indicators,
	}).Debug("Extracted CVE indicators")

	return indicators
}

// extractCVEPatterns extracts CVE identifiers from text
func (c *CVEClassifier) extractCVEPatterns(text string) []string {
	var patterns []string

	// Convert to uppercase for consistent matching
	upperText := strings.ToUpper(text)

	// Look for CVE pattern directly in the text using string searching
	// Don't split on hyphens since that would break CVE-YYYY-NNNN
	words := strings.FieldsFunc(upperText, func(r rune) bool {
		return r == ' ' || r == '/' || r == '_' || r == '.' || r == '\t' || r == '\n'
	})

	// Also check the whole text for CVE patterns
	allTexts := append(words, upperText)

	for _, textToCheck := range allTexts {
		// Look for CVE patterns in this text
		if strings.Contains(textToCheck, "CVE-") {
			// Find all CVE patterns in this text
			start := 0
			for {
				index := strings.Index(textToCheck[start:], "CVE-")
				if index == -1 {
					break
				}

				actualStart := start + index
				remaining := textToCheck[actualStart:]

				// Extract CVE pattern
				if len(remaining) >= 13 { // Minimum CVE length
					// Find end of CVE pattern - look for space, underscore, or end of string
					endIndex := len(remaining)
					for i, char := range remaining {
						if i > 13 && (char == ' ' || char == '_' || char == '.' || char == '/' || char == '\t') {
							endIndex = i
							break
						}
					}

					potentialCVE := remaining[:endIndex]
					if len(potentialCVE) >= 13 && isValidCVEPattern(potentialCVE) {
						patterns = append(patterns, potentialCVE)
					}
				}

				start = actualStart + 4 // Move past "CVE-"
			}
		}
	}

	logrus.WithFields(logrus.Fields{
		"text":     text,
		"words":    words,
		"patterns": patterns,
	}).Debug("Extracted CVE patterns")

	return patterns
}

// isValidCVEPattern checks if a string matches CVE-YYYY-NNNN pattern
func isValidCVEPattern(s string) bool {
	if len(s) < 13 || !strings.HasPrefix(s, "CVE-") {
		return false
	}

	// Check if it has the right format: CVE-YYYY-NNNN+
	parts := strings.Split(s, "-")
	if len(parts) < 3 {
		return false
	}

	// parts[0] should be "CVE"
	// parts[1] should be 4 digits (year)
	// parts[2] should be at least 4 digits
	if parts[0] != "CVE" {
		return false
	}

	if len(parts[1]) != 4 {
		return false
	}

	if len(parts[2]) < 4 {
		return false
	}

	// Check if year and number parts are digits
	for _, char := range parts[1] {
		if char < '0' || char > '9' {
			return false
		}
	}

	for i, char := range parts[2] {
		if i < 4 && (char < '0' || char > '9') {
			return false
		}
	}

	return true
}

// extractSecurityKeywords extracts security-relevant keywords
func (c *CVEClassifier) extractSecurityKeywords(text string) []string {
	keywords := []string{
		"exploit", "vulnerability", "malware", "backdoor", "trojan",
		"ransomware", "spyware", "rootkit", "botnet", "shellcode",
		"buffer overflow", "injection", "xss", "csrf", "privilege escalation",
		"pkexec", "log4j", "jndi", "ldap", "setuid", "polkit",
	}

	var found []string
	lowerText := strings.ToLower(text)

	for _, keyword := range keywords {
		if strings.Contains(lowerText, keyword) {
			found = append(found, keyword)
		}
	}

	logrus.WithFields(logrus.Fields{
		"text":     text,
		"keywords": found,
	}).Debug("Extracted security keywords")

	return found
}

// classifyByKeywords performs keyword-based CVE classification
func (c *CVEClassifier) classifyByKeywords(event *pb.SecurityEvent, indicators []string) (Severity, string) {
	for _, cveEntry := range c.cveDatabase {
		for _, cveKeyword := range cveEntry.Keywords {
			for _, indicator := range indicators {
				if strings.Contains(strings.ToLower(indicator), strings.ToLower(cveKeyword)) {
					logrus.WithFields(logrus.Fields{
						"matched_keyword": cveKeyword,
						"indicator":       indicator,
						"cve_id":          cveEntry.ID,
					}).Debug("Found CVE keyword match")
					return c.createClassificationFromCVE(event, cveEntry)
				}
			}
		}
	}

	return "", ""
}

// createClassificationFromCVE creates a classification based on CVE data
func (c *CVEClassifier) createClassificationFromCVE(event *pb.SecurityEvent, cve *CVEEntry) (Severity, string) {
	severity := c.mapCVSSToSeverity(cve.CVSS)

	description := fmt.Sprintf("CVE Match: %s - %s (CVSS: %.1f)",
		cve.ID,
		cve.Description[:min(100, len(cve.Description))],
		cve.CVSS)

	return severity, description
}

// mapCVSSToSeverity maps CVSS score to our severity levels
func (c *CVEClassifier) mapCVSSToSeverity(cvss float64) Severity {
	switch {
	case cvss >= 9.0:
		return SeverityCritical
	case cvss >= 7.0:
		return SeverityHigh
	case cvss >= 4.0:
		return SeverityWarn
	case cvss > 0.0:
		return SeverityLow
	default:
		return SeverityLow
	}
}

// loadCVEData loads CVE data from local file
func (c *CVEClassifier) loadCVEData() error {
	if _, err := os.Stat(c.dataPath); os.IsNotExist(err) {
		logrus.WithField("path", c.dataPath).Info("CVE data file doesn't exist, will create on first update")
		return nil
	}

	data, err := os.ReadFile(c.dataPath)
	if err != nil {
		return fmt.Errorf("failed to read CVE data file: %w", err)
	}

	var cveData map[string]*CVEEntry
	if err := json.Unmarshal(data, &cveData); err != nil {
		return fmt.Errorf("failed to unmarshal CVE data: %w", err)
	}

	c.cveDatabase = cveData
	c.lastUpdate = time.Now()

	logrus.WithField("count", len(c.cveDatabase)).Info("Loaded CVE database")
	return nil
}

// saveCVEData saves CVE data to local file
func (c *CVEClassifier) saveCVEData() error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(c.dataPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	data, err := json.MarshalIndent(c.cveDatabase, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal CVE data: %w", err)
	}

	if err := os.WriteFile(c.dataPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write CVE data file: %w", err)
	}

	logrus.WithField("path", c.dataPath).Debug("CVE data saved")
	return nil
}

// startUpdateRoutine starts the background CVE data update routine
func (c *CVEClassifier) startUpdateRoutine() {
	ticker := time.NewTicker(c.updateInterval)
	defer ticker.Stop()

	// Initial update if database is empty or old
	if len(c.cveDatabase) == 0 || time.Since(c.lastUpdate) > c.updateInterval {
		if err := c.updateCVEData(); err != nil {
			logrus.WithError(err).Error("Initial CVE data update failed")
		}
	}

	for range ticker.C {
		if err := c.updateCVEData(); err != nil {
			logrus.WithError(err).Error("CVE data update failed")
		}
	}
}

// updateCVEData fetches fresh CVE data from NIST NVD API
func (c *CVEClassifier) updateCVEData() error {
	c.apiCalls++

	logrus.Info("Updating CVE database from NIST NVD API")

	// For demo purposes, fetch recent CVEs (last 30 days)
	endDate := time.Now()
	startDate := endDate.AddDate(0, 0, -30)

	url := fmt.Sprintf("%s?pubStartDate=%s&pubEndDate=%s&resultsPerPage=100",
		c.apiEndpoint,
		startDate.Format("2006-01-02T15:04:05.000"),
		endDate.Format("2006-01-02T15:04:05.000"))

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if c.apiKey != "" {
		req.Header.Set("X-API-KEY", c.apiKey)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch CVE data: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API request failed with status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	var nvdResponse NVDResponse
	if err := json.Unmarshal(body, &nvdResponse); err != nil {
		return fmt.Errorf("failed to unmarshal NVD response: %w", err)
	}

	// Process and store CVE entries
	c.mu.Lock()
	newEntries := 0
	for _, result := range nvdResponse.Results {
		cve := result.CVE

		// Extract description
		description := ""
		for _, desc := range cve.Descriptions {
			if desc.Lang == "en" {
				description = desc.Value
				break
			}
		}

		// Extract CVSS score and severity
		cvss := 0.0
		severity := "UNKNOWN"
		if len(cve.Metrics.CVSSMetricV31) > 0 {
			cvss = cve.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
			severity = cve.Metrics.CVSSMetricV31[0].CVSSData.BaseSeverity
		}

		// Extract references
		var references []string
		for _, ref := range cve.References {
			references = append(references, ref.URL)
		}

		// Generate keywords from description
		keywords := c.generateKeywordsFromDescription(description)

		entry := &CVEEntry{
			ID:          cve.ID,
			Description: description,
			CVSS:        cvss,
			Severity:    severity,
			References:  references,
			Keywords:    keywords,
			Published:   cve.Published,
			Modified:    cve.Modified,
		}

		if _, exists := c.cveDatabase[cve.ID]; !exists {
			newEntries++
		}
		c.cveDatabase[cve.ID] = entry
	}
	c.lastUpdate = time.Now()
	c.mu.Unlock()

	// Save updated data
	if err := c.saveCVEData(); err != nil {
		logrus.WithError(err).Error("Failed to save updated CVE data")
	}

	logrus.WithFields(logrus.Fields{
		"total_cves":  len(c.cveDatabase),
		"new_entries": newEntries,
		"api_results": nvdResponse.TotalResults,
	}).Info("CVE database updated")

	return nil
}

// generateKeywordsFromDescription extracts keywords from CVE description
func (c *CVEClassifier) generateKeywordsFromDescription(description string) []string {
	var keywords []string

	// Common security keywords to extract
	securityTerms := []string{
		"buffer overflow", "code injection", "sql injection", "xss", "csrf",
		"privilege escalation", "remote code execution", "denial of service",
		"authentication bypass", "directory traversal", "information disclosure",
		"memory corruption", "use after free", "null pointer dereference",
	}

	lowerDesc := strings.ToLower(description)
	for _, term := range securityTerms {
		if strings.Contains(lowerDesc, term) {
			keywords = append(keywords, term)
		}
	}

	return keywords
}

// GetMetrics returns classifier metrics
func (c *CVEClassifier) GetMetrics() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return map[string]interface{}{
		"total_classifications": c.classifications,
		"cve_matches":           c.cveMatches,
		"api_calls":             c.apiCalls,
		"cve_database_size":     len(c.cveDatabase),
		"last_update":           c.lastUpdate.Format(time.RFC3339),
		"classifier_type":       "cve",
	}
}

// Helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
