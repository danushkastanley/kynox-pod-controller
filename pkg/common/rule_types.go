package common

// Event matching and classification rule types

// EventMatch represents a pattern that matches specific events
type EventMatch struct {
	EventType       string           `yaml:"event_type"`
	CommandPatterns []string         `yaml:"command_patterns,omitempty"`
	FilePatterns    []string         `yaml:"file_patterns,omitempty"`
	NetworkPatterns []NetworkPattern `yaml:"network_patterns,omitempty"`
	Conditions      []MatchCondition `yaml:"conditions,omitempty"`
}

// NetworkPattern represents network-based matching patterns
type NetworkPattern struct {
	Ports               []int    `yaml:"ports,omitempty"`
	DestinationRanges   []string `yaml:"destination_ranges,omitempty"`
	SuspiciousProcess   bool     `yaml:"suspicious_process,omitempty"`
	ExternalDestination bool     `yaml:"external_destination,omitempty"`
}

// MatchCondition represents a conditional match
type MatchCondition struct {
	Field    string `yaml:"field"`
	Operator string `yaml:"operator"` // equals, not_equals, contains, matches
	Value    string `yaml:"value"`
}

// MITRE ATT&CK Classification Types

// TechniqueMapping maps events to MITRE ATT&CK techniques
type TechniqueMapping struct {
	TechniqueID    string       `yaml:"technique_id"`
	TechniqueName  string       `yaml:"technique_name"`
	Tactic         string       `yaml:"tactic"`
	SubTechniques  []string     `yaml:"sub_techniques,omitempty"`
	EventMatches   []EventMatch `yaml:"event_matches"`
	Confidence     float64      `yaml:"confidence"`
	RequiredFields []string     `yaml:"required_fields,omitempty"`
}

// TacticMapping maps tactics to techniques
type TacticMapping struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Techniques  []string `yaml:"techniques"`
}

// DataSourceMapping maps data sources to event types
type DataSourceMapping struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	EventTypes  []string `yaml:"event_types"`
}

// CVE Classification Types

// CVEMapping maps events to CVE references
type CVEMapping struct {
	CVEID        string          `yaml:"cve_id"`
	Severity     string          `yaml:"severity"`
	Score        float64         `yaml:"score"`
	EventMatches []EventMatch    `yaml:"event_matches"`
	Software     []SoftwareMatch `yaml:"software,omitempty"`
	Exploits     []ExploitInfo   `yaml:"exploits,omitempty"`
}

// SoftwareMatch identifies affected software
type SoftwareMatch struct {
	Name         string `yaml:"name"`
	VersionRange string `yaml:"version_range"`
	Path         string `yaml:"path,omitempty"`
}

// ExploitInfo provides information about exploits
type ExploitInfo struct {
	Type        string   `yaml:"type"`
	Description string   `yaml:"description"`
	References  []string `yaml:"references,omitempty"`
}

// Custom Framework Classification Types

// CustomFrameworkRule represents a user-defined classification rule
type CustomFrameworkRule struct {
	Framework  string            `yaml:"framework"`
	Category   string            `yaml:"category"`
	Patterns   []string          `yaml:"patterns"`
	Conditions []MatchCondition  `yaml:"conditions"`
	Confidence float64           `yaml:"confidence"`
	Metadata   map[string]string `yaml:"metadata,omitempty"`
}

// Threat Intelligence Types

// ThreatIntelSource represents a threat intelligence source
type ThreatIntelSource struct {
	Name    string `yaml:"name"`
	Type    string `yaml:"type"` // "feed", "api", "file"
	URL     string `yaml:"url,omitempty"`
	APIKey  string `yaml:"api_key,omitempty"`
	Enabled bool   `yaml:"enabled"`
}

// ThreatIntelMapping maps events to threat intelligence
type ThreatIntelMapping struct {
	ThreatActor  string       `yaml:"threat_actor,omitempty"`
	Campaign     string       `yaml:"campaign,omitempty"`
	Malware      string       `yaml:"malware,omitempty"`
	EventMatches []EventMatch `yaml:"event_matches"`
	IOCs         []string     `yaml:"iocs,omitempty"`
}
