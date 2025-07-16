package classifier

import (
	"testing"
	"time"

	pb "pod-controller/pkg/telemetry"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock threat detector for testing
type mockThreatDetector struct{}

func (m *mockThreatDetector) IsSuspiciousCommand(cmd string) bool {
	return false
}

func (m *mockThreatDetector) IsSuspiciousFileAccess(path string) bool {
	return false
}

func (m *mockThreatDetector) IsSuspiciousChmod(path string, mode uint32) bool {
	return false
}

func (m *mockThreatDetector) IsExternalConnection(ip string) bool {
	return false
}

func TestCVEClassifier_Basic(t *testing.T) {
	// Create test configuration
	config := &ClassifierConfig{
		Type:              ClassifierTypeCVE,
		CVEDataPath:       "../../data/sample-cve-data.json",
		CVEAPIKey:         "",
		CVEAPIEndpoint:    "https://services.nvd.nist.gov/rest/json/cves/2.0",
		CVEUpdateInterval: 24 * time.Hour,
		ThreatDetector:    &mockThreatDetector{},
		FallbackEnabled:   true,
	}

	// Create CVE classifier
	classifier, err := NewCVEClassifier(config)
	require.NoError(t, err, "Failed to create CVE classifier")
	require.NotNil(t, classifier, "Classifier should not be nil")

	// Wait a moment for data to load
	time.Sleep(100 * time.Millisecond)

	// Verify classifier implements the interface
	var _ EventClassifierInterface = classifier
}

func TestCVEClassifier_DirectCVEMatch(t *testing.T) {
	config := &ClassifierConfig{
		Type:              ClassifierTypeCVE,
		CVEDataPath:       "../../data/sample-cve-data.json",
		CVEAPIKey:         "",
		CVEAPIEndpoint:    "https://services.nvd.nist.gov/rest/json/cves/2.0",
		CVEUpdateInterval: 24 * time.Hour,
		ThreatDetector:    &mockThreatDetector{},
		FallbackEnabled:   true,
	}

	classifier, err := NewCVEClassifier(config)
	require.NoError(t, err)

	// Wait for data to load
	time.Sleep(100 * time.Millisecond)

	// Test event with CVE reference in command
	event := &pb.SecurityEvent{
		EventType: pb.EventType_EXEC,
		Pid:       1234,
		Command:   "exploit_CVE-2021-44228.sh",
		FilePath:  "/tmp/exploit.sh",
		Uid:       1000,
	}

	severity, description := classifier.ClassifyEvent(event)

	// Should detect the CVE and classify as CRITICAL
	assert.Equal(t, SeverityCritical, severity, "Should classify log4j CVE as critical")
	assert.Contains(t, description, "CVE-2021-44228", "Description should contain CVE ID")
	assert.Contains(t, description, "CVSS: 10.0", "Description should contain CVSS score")
}

func TestCVEClassifier_KeywordMatch(t *testing.T) {
	config := &ClassifierConfig{
		Type:              ClassifierTypeCVE,
		CVEDataPath:       "../../data/sample-cve-data.json",
		CVEAPIKey:         "",
		CVEAPIEndpoint:    "https://services.nvd.nist.gov/rest/json/cves/2.0",
		CVEUpdateInterval: 24 * time.Hour,
		ThreatDetector:    &mockThreatDetector{},
		FallbackEnabled:   true,
	}

	classifier, err := NewCVEClassifier(config)
	require.NoError(t, err)

	// Wait for data to load
	time.Sleep(100 * time.Millisecond)

	// Test event with keyword that matches CVE
	event := &pb.SecurityEvent{
		EventType: pb.EventType_EXEC,
		Pid:       1234,
		Command:   "pkexec /bin/bash",
		FilePath:  "/usr/bin/pkexec",
		Uid:       1000,
	}

	severity, description := classifier.ClassifyEvent(event)

	// Should detect pkexec keyword and match to CVE-2021-4034
	assert.Equal(t, SeverityHigh, severity, "Should classify pkexec as high severity")
	assert.Contains(t, description, "CVE", "Description should contain CVE reference")
}

func TestCVEClassifier_NoMatch_FallsBack(t *testing.T) {
	config := &ClassifierConfig{
		Type:              ClassifierTypeCVE,
		CVEDataPath:       "../../data/sample-cve-data.json",
		CVEAPIKey:         "",
		CVEAPIEndpoint:    "https://services.nvd.nist.gov/rest/json/cves/2.0",
		CVEUpdateInterval: 24 * time.Hour,
		ThreatDetector:    &mockThreatDetector{},
		FallbackEnabled:   true,
	}

	classifier, err := NewCVEClassifier(config)
	require.NoError(t, err)

	// Wait for data to load
	time.Sleep(100 * time.Millisecond)

	// Test normal event that shouldn't match any CVE
	event := &pb.SecurityEvent{
		EventType: pb.EventType_OPEN,
		Pid:       1234,
		Command:   "cat",
		FilePath:  "/etc/passwd",
		Uid:       1000,
	}

	severity, description := classifier.ClassifyEvent(event)

	// Should fall back to default classifier behavior
	assert.NotEmpty(t, severity, "Should return some severity")
	assert.NotEmpty(t, description, "Should return some description")
	// Should not contain CVE reference since no match
	assert.NotContains(t, description, "CVE", "Should not contain CVE reference for normal events")
}

func TestCVEClassifier_Metrics(t *testing.T) {
	config := &ClassifierConfig{
		Type:              ClassifierTypeCVE,
		CVEDataPath:       "../../data/sample-cve-data.json",
		CVEAPIKey:         "",
		CVEAPIEndpoint:    "https://services.nvd.nist.gov/rest/json/cves/2.0",
		CVEUpdateInterval: 24 * time.Hour,
		ThreatDetector:    &mockThreatDetector{},
		FallbackEnabled:   true,
	}

	classifier, err := NewCVEClassifier(config)
	require.NoError(t, err)

	// Wait for data to load
	time.Sleep(100 * time.Millisecond)

	// Test several events
	events := []*pb.SecurityEvent{
		{
			EventType: pb.EventType_EXEC,
			Command:   "exploit_CVE-2021-44228.sh",
			Uid:       1000,
		},
		{
			EventType: pb.EventType_EXEC,
			Command:   "normal_command",
			Uid:       1000,
		},
		{
			EventType: pb.EventType_EXEC,
			Command:   "pkexec test",
			Uid:       1000,
		},
	}

	for _, event := range events {
		classifier.ClassifyEvent(event)
	}

	// Check metrics
	metrics := classifier.GetMetrics()

	assert.Equal(t, int64(3), metrics["total_classifications"], "Should track total classifications")
	assert.GreaterOrEqual(t, metrics["cve_matches"].(int64), int64(1), "Should have at least one CVE match")
	assert.Equal(t, "cve", metrics["classifier_type"], "Should report correct classifier type")
	assert.GreaterOrEqual(t, metrics["cve_database_size"].(int), 1, "Should have loaded CVE data")
}

func TestCVEClassifier_PatternExtraction(t *testing.T) {
	config := &ClassifierConfig{
		Type:           ClassifierTypeCVE,
		CVEDataPath:    "../../data/sample-cve-data.json",
		ThreatDetector: &mockThreatDetector{},
	}

	classifier, err := NewCVEClassifier(config)
	require.NoError(t, err)

	// Test CVE pattern extraction
	patterns := classifier.extractCVEPatterns("Testing CVE-2021-44228 exploit")
	assert.Contains(t, patterns, "CVE-2021-44228", "Should extract CVE pattern")

	// Test keyword extraction
	keywords := classifier.extractSecurityKeywords("This is a privilege escalation exploit")
	assert.Contains(t, keywords, "privilege escalation", "Should extract security keywords")
	assert.Contains(t, keywords, "exploit", "Should extract exploit keyword")
}
