package rules

import (
	"time"

	"pod-controller/pkg/common"
)

// SecurityRules represents the complete rule configuration
type SecurityRules struct {
	APIVersion    string                     `yaml:"apiVersion"`
	Kind          string                     `yaml:"kind"`
	Metadata      RuleMetadata               `yaml:"metadata"`
	Global        GlobalConfig               `yaml:"global"`
	EventTypes    map[string]EventTypeConfig `yaml:"event_types"`
	Commands      CommandRules               `yaml:"commands"`
	Filesystem    FilesystemRules            `yaml:"filesystem"`
	Network       NetworkRules               `yaml:"network"`
	Process       ProcessRules               `yaml:"process"`
	Containers    ContainerRules             `yaml:"containers"`
	CustomRules   CustomRules                `yaml:"custom_rules"`
	Notifications NotificationRules          `yaml:"notifications"`

	// New classification sections
	MitreAttack     MitreAttackRules     `yaml:"mitre_attack"`
	CVEMappings     CVEMappingRules      `yaml:"cve_mappings"`
	CustomFramework CustomFrameworkRules `yaml:"custom_framework"`
	ThreatIntel     ThreatIntelRules     `yaml:"threat_intel"`
}

// RuleMetadata contains metadata about the rules
type RuleMetadata struct {
	Name          string    `yaml:"name"`
	Version       string    `yaml:"version"`
	Description   string    `yaml:"description"`
	LastUpdated   time.Time `yaml:"last_updated"`
	CreatedBy     string    `yaml:"created_by"`
	Tags          []string  `yaml:"tags"`
	Documentation string    `yaml:"documentation"`
}

// GlobalConfig contains global monitoring settings
type GlobalConfig struct {
	DefaultSeverity          string          `yaml:"default_severity"`
	EnableProcessMonitoring  bool            `yaml:"enable_process_monitoring"`
	EnableNetworkMonitoring  bool            `yaml:"enable_network_monitoring"`
	EnableFileMonitoring     bool            `yaml:"enable_file_monitoring"`
	EnableSecurityMonitoring bool            `yaml:"enable_security_monitoring"`
	RateLimit                RateLimitConfig `yaml:"rate_limit"`
	AlertAggregation         AlertAggConfig  `yaml:"alert_aggregation"`
}

// RateLimitConfig defines rate limiting settings
type RateLimitConfig struct {
	EventsPerSecond int `yaml:"events_per_second"`
	BurstSize       int `yaml:"burst_size"`
}

// AlertAggConfig defines alert aggregation settings
type AlertAggConfig struct {
	WindowMinutes int `yaml:"window_minutes"`
	MaxCount      int `yaml:"max_count"`
}

// EventTypeConfig defines configuration for specific event types
type EventTypeConfig struct {
	Enabled         bool   `yaml:"enabled"`
	DefaultSeverity string `yaml:"default_severity"`
	MonitorAll      bool   `yaml:"monitor_all"`
}

// CommandRules defines command monitoring rules
type CommandRules struct {
	Suspicious []CommandRule `yaml:"suspicious"`
	Trusted    []CommandRule `yaml:"trusted"`
}

// CommandRule defines a rule for command monitoring
type CommandRule struct {
	Name       string             `yaml:"name"`
	Severity   string             `yaml:"severity"`
	Patterns   []string           `yaml:"patterns"`
	Conditions []CommandCondition `yaml:"conditions"`
}

// CommandCondition defines conditions that modify command rule behavior
type CommandCondition struct {
	UIDIsRoot             bool   `yaml:"uid_is_root,omitempty"`
	ExternalNetwork       bool   `yaml:"external_network,omitempty"`
	InContainer           bool   `yaml:"in_container,omitempty"`
	TargetIsSensitive     bool   `yaml:"target_is_sensitive,omitempty"`
	TargetPIDIsPrivileged bool   `yaml:"target_pid_is_privileged,omitempty"`
	UnauthorizedContext   bool   `yaml:"unauthorized_context,omitempty"`
	ExternalDestination   bool   `yaml:"external_destination,omitempty"`
	Severity              string `yaml:"severity,omitempty"`
	EscalateSeverity      string `yaml:"escalate_severity,omitempty"`
}

// FilesystemRules defines filesystem monitoring rules
type FilesystemRules struct {
	SensitiveFiles       []FileRule  `yaml:"sensitive_files"`
	SensitiveDirectories []FileRule  `yaml:"sensitive_directories"`
	WatchPaths           []WatchPath `yaml:"watch_paths"`
}

// FileRule defines a rule for file/directory monitoring
type FileRule struct {
	Name       string          `yaml:"name"`
	Severity   string          `yaml:"severity"`
	Paths      []string        `yaml:"paths"`
	Conditions []FileCondition `yaml:"conditions"`
}

// FileCondition defines conditions for file access rules
type FileCondition struct {
	UIDIsRoot          bool   `yaml:"uid_is_root,omitempty"`
	WriteAccess        bool   `yaml:"write_access,omitempty"`
	UnauthorizedAccess bool   `yaml:"unauthorized_access,omitempty"`
	Severity           string `yaml:"severity,omitempty"`
}

// WatchPath defines a path to actively monitor
type WatchPath struct {
	Name             string          `yaml:"name"`
	Paths            []string        `yaml:"paths"`
	Events           []string        `yaml:"events"`
	Severity         string          `yaml:"severity"`
	Conditions       []FileCondition `yaml:"conditions"`
	ExcludeProcesses []string        `yaml:"exclude_processes"`
}

// NetworkRules defines network monitoring rules
type NetworkRules struct {
	SuspiciousPorts  []NetworkPortRule `yaml:"suspicious_ports"`
	ExternalNetworks []ExternalNetwork `yaml:"external_networks"`
	PrivateNetworks  []string          `yaml:"private_networks"`
}

// NetworkPortRule defines rules for network port monitoring
type NetworkPortRule struct {
	Name       string             `yaml:"name"`
	Severity   string             `yaml:"severity"`
	Ports      []int              `yaml:"ports"`
	Conditions []NetworkCondition `yaml:"conditions"`
}

// NetworkCondition defines conditions for network rules
type NetworkCondition struct {
	ExternalDestination bool   `yaml:"external_destination,omitempty"`
	UnauthorizedProcess bool   `yaml:"unauthorized_process,omitempty"`
	Severity            string `yaml:"severity,omitempty"`
	EscalateSeverity    string `yaml:"escalate_severity,omitempty"`
}

// ExternalNetwork defines external network ranges to monitor
type ExternalNetwork struct {
	Name     string   `yaml:"name"`
	Severity string   `yaml:"severity"`
	Ranges   []string `yaml:"ranges"`
}

// ProcessRules defines process monitoring rules
type ProcessRules struct {
	SpawnLimits         map[string]SpawnLimit `yaml:"spawn_limits"`
	ResourceLimits      ResourceLimits        `yaml:"resource_limits"`
	PrivilegeEscalation PrivilegeEscalation   `yaml:"privilege_escalation"`
}

// SpawnLimit defines process spawn rate limits
type SpawnLimit struct {
	MaxPerMinute int    `yaml:"max_per_minute"`
	Severity     string `yaml:"severity"`
}

// ResourceLimits defines resource usage limits
type ResourceLimits struct {
	MemoryThresholdMB   int `yaml:"memory_threshold_mb"`
	CPUThresholdPercent int `yaml:"cpu_threshold_percent"`
}

// PrivilegeEscalation defines privilege escalation monitoring
type PrivilegeEscalation struct {
	SetuidMonitoring     bool   `yaml:"setuid_monitoring"`
	SetgidMonitoring     bool   `yaml:"setgid_monitoring"`
	CapabilityMonitoring bool   `yaml:"capability_monitoring"`
	Severity             string `yaml:"severity"`
}

// ContainerRules defines container-specific rules
type ContainerRules struct {
	DefaultPolicy ContainerPolicy   `yaml:"default_policy"`
	Policies      []ContainerPolicy `yaml:"policies"`
}

// ContainerPolicy defines policies for containers
type ContainerPolicy struct {
	Name               string               `yaml:"name"`
	Patterns           []string             `yaml:"patterns"`
	MonitorPrivileged  bool                 `yaml:"monitor_privileged"`
	MonitorHostNetwork bool                 `yaml:"monitor_host_network"`
	MonitorHostPID     bool                 `yaml:"monitor_host_pid"`
	Rules              ContainerPolicyRules `yaml:"rules"`
}

// ContainerPolicyRules defines specific rules for container policies
type ContainerPolicyRules struct {
	ReducedMonitoring  bool `yaml:"reduced_monitoring"`
	SeverityAdjustment int  `yaml:"severity_adjustment"`
	TrustedProcesses   bool `yaml:"trusted_processes"`
}

// CustomRules defines environment-specific custom rules
type CustomRules struct {
	Development EnvironmentRules `yaml:"development"`
	Production  EnvironmentRules `yaml:"production"`
}

// EnvironmentRules defines rules for specific environments
type EnvironmentRules struct {
	Enabled bool                   `yaml:"enabled"`
	Rules   map[string]interface{} `yaml:"rules"`
}

// NotificationRules defines notification and alerting rules
type NotificationRules struct {
	Routing map[string]NotificationRoute `yaml:"routing"`
}

// NotificationRoute defines how alerts are routed based on severity
type NotificationRoute struct {
	Immediate    bool     `yaml:"immediate,omitempty"`
	DelaySeconds int      `yaml:"delay_seconds,omitempty"`
	Channels     []string `yaml:"channels"`
}

// RuleEvaluationContext provides context for rule evaluation
type RuleEvaluationContext struct {
	Command         string
	FilePath        string
	UID             int32
	GID             int32
	PID             int32
	IsRoot          bool
	IsContainer     bool
	IsPrivileged    bool
	DestinationIP   string
	DestinationPort int32
	WriteAccess     bool
	ExternalNetwork bool
	ContainerID     string
	Namespace       string
	PodName         string
}

// SeverityLevel represents security severity levels
type SeverityLevel int

const (
	SeverityLow SeverityLevel = iota
	SeverityWarn
	SeverityHigh
	SeverityCritical
)

// String returns string representation of severity level
func (s SeverityLevel) String() string {
	switch s {
	case SeverityLow:
		return "LOW"
	case SeverityWarn:
		return "WARN"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// ToCommonSeverity converts to common.Severity
func (s SeverityLevel) ToCommonSeverity() common.Severity {
	switch s {
	case SeverityLow:
		return common.SeverityLow
	case SeverityWarn:
		return common.SeverityWarn
	case SeverityHigh:
		return common.SeverityHigh
	case SeverityCritical:
		return common.SeverityCritical
	default:
		return common.SeverityLow
	}
}

// ParseSeverity converts string to SeverityLevel
func ParseSeverity(severity string) SeverityLevel {
	switch severity {
	case "LOW":
		return SeverityLow
	case "WARN":
		return SeverityWarn
	case "HIGH":
		return SeverityHigh
	case "CRITICAL":
		return SeverityCritical
	default:
		return SeverityLow
	}
}

// MitreAttackRules contains MITRE ATT&CK classification rules
type MitreAttackRules struct {
	Enabled     bool                       `yaml:"enabled"`
	Version     string                     `yaml:"version"` // MITRE ATT&CK version
	Techniques  []common.TechniqueMapping  `yaml:"techniques"`
	Tactics     []common.TacticMapping     `yaml:"tactics"`
	DataSources []common.DataSourceMapping `yaml:"data_sources"`
}

// CVEMappingRules contains CVE classification rules
type CVEMappingRules struct {
	Enabled      bool                `yaml:"enabled"`
	AutoUpdate   bool                `yaml:"auto_update"`
	UpdateSource string              `yaml:"update_source"`
	Mappings     []common.CVEMapping `yaml:"mappings"`
}

// CustomFrameworkRules contains custom classification framework rules
type CustomFrameworkRules struct {
	Enabled bool                                  `yaml:"enabled"`
	Rules   map[string]common.CustomFrameworkRule `yaml:"rules"`
}

// ThreatIntelRules contains threat intelligence rules
type ThreatIntelRules struct {
	Enabled        bool                        `yaml:"enabled"`
	Sources        []common.ThreatIntelSource  `yaml:"sources"`
	Mappings       []common.ThreatIntelMapping `yaml:"mappings"`
	UpdateInterval string                      `yaml:"update_interval"`
}
