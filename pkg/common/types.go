package common

import "time"

// Severity levels for security events
type Severity string

const (
	SeverityLow      Severity = "LOW"
	SeverityWarn     Severity = "WARN"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// AttackTechnique represents a MITRE ATT&CK technique mapping
type AttackTechnique struct {
	TechniqueID   string   `json:"technique_id"`   // e.g., "T1055"
	TechniqueName string   `json:"technique_name"` // e.g., "Process Injection"
	Tactic        string   `json:"tactic"`         // e.g., "Defense Evasion"
	SubTechnique  string   `json:"sub_technique,omitempty"`
	Confidence    float64  `json:"confidence"` // 0.0 to 1.0
	DataSources   []string `json:"data_sources,omitempty"`
}

// CVEReference represents a CVE reference
type CVEReference struct {
	CVEID            string   `json:"cve_id"` // e.g., "CVE-2023-1234"
	Description      string   `json:"description"`
	Severity         string   `json:"severity"` // CVSS rating
	Score            float64  `json:"score"`    // CVSS score
	AffectedSoftware []string `json:"affected_software,omitempty"`
	References       []string `json:"references,omitempty"`
}

// ThreatIntel represents threat intelligence information
type ThreatIntel struct {
	ThreatActors []string `json:"threat_actors,omitempty"`
	Campaigns    []string `json:"campaigns,omitempty"`
	Malware      []string `json:"malware,omitempty"`
	IOCs         []string `json:"iocs,omitempty"` // Indicators of Compromise
}

// Classification represents a security framework classification
type Classification struct {
	Framework   string            `json:"framework"` // "MITRE", "CVE", "CUSTOM"
	Category    string            `json:"category"`
	Subcategory string            `json:"subcategory,omitempty"`
	Confidence  float64           `json:"confidence"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// ClassificationResult contains all classification results from different engines
type ClassificationResult struct {
	AttackTechniques []AttackTechnique `json:"attack_techniques,omitempty"`
	CVEReferences    []CVEReference    `json:"cve_references,omitempty"`
	ThreatIntel      *ThreatIntel      `json:"threat_intel,omitempty"`
	Classifications  []Classification  `json:"classifications,omitempty"`
}

// EventContext provides context for event classification
type EventContext struct {
	EventType       string            `json:"event_type"`
	Command         string            `json:"command,omitempty"`
	FilePath        string            `json:"file_path,omitempty"`
	UID             int32             `json:"uid"`
	GID             int32             `json:"gid"`
	PID             int32             `json:"pid"`
	IsRoot          bool              `json:"is_root"`
	IsContainer     bool              `json:"is_container"`
	IsPrivileged    bool              `json:"is_privileged"`
	DestinationIP   string            `json:"destination_ip,omitempty"`
	DestinationPort int32             `json:"destination_port,omitempty"`
	SourcePort      int32             `json:"source_port,omitempty"`
	Mode            uint32            `json:"mode,omitempty"`
	WriteAccess     bool              `json:"write_access"`
	ExternalNetwork bool              `json:"external_network"`
	ContainerID     string            `json:"container_id"`
	Namespace       string            `json:"namespace"`
	PodName         string            `json:"pod_name"`
	AdditionalData  map[string]string `json:"additional_data,omitempty"`
	Timestamp       time.Time         `json:"timestamp"`
}
