package filter

import (
	"os"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

// NamespaceFilter manages which namespaces should be monitored
type NamespaceFilter struct {
	mu sync.RWMutex

	// Namespaces to exclude from monitoring (system namespaces)
	excludedNamespaces map[string]bool

	// Namespaces to explicitly include (if set, ONLY these are monitored)
	includedNamespaces map[string]bool

	// If true, use include list; if false, use exclude list
	useIncludeMode bool
}

// Default system namespaces that should be excluded from monitoring
var defaultExcludedNamespaces = []string{
	"kube-system",
	"kube-public",
	"kube-node-lease",
	"calico-system",
	"calico-apiserver",
	"tigera-operator",
	"cilium",
	"flannel",
	"weave",
	"istio-system",
	"linkerd",
	"ingress-nginx",
	"cert-manager",
	"metallb-system",
	"local-path-storage",
	"monitoring",        // Prometheus, Grafana
	"logging",           // ELK, Loki
	"flux-system",       // GitOps
	"argocd",            // GitOps
	"security",          // Security tools (including our agent potentially)
	"gatekeeper-system", // OPA Gatekeeper
}

// NewNamespaceFilter creates a new namespace filter with default settings
func NewNamespaceFilter() *NamespaceFilter {
	nf := &NamespaceFilter{
		excludedNamespaces: make(map[string]bool),
		includedNamespaces: make(map[string]bool),
		useIncludeMode:     false,
	}

	// Load defaults
	for _, ns := range defaultExcludedNamespaces {
		nf.excludedNamespaces[ns] = true
	}

	// Load from environment
	nf.loadFromEnvironment()

	return nf
}

// loadFromEnvironment loads configuration from environment variables
func (nf *NamespaceFilter) loadFromEnvironment() {
	// MONITOR_NAMESPACES: comma-separated list of namespaces to monitor (include mode)
	// If set, ONLY these namespaces will be monitored
	if includeList := os.Getenv("MONITOR_NAMESPACES"); includeList != "" {
		nf.useIncludeMode = true
		for _, ns := range strings.Split(includeList, ",") {
			ns = strings.TrimSpace(ns)
			if ns != "" {
				nf.includedNamespaces[ns] = true
			}
		}
		logrus.WithField("namespaces", includeList).Info("Monitoring only specified namespaces (include mode)")
	}

	// EXCLUDE_NAMESPACES: comma-separated list of additional namespaces to exclude
	if excludeList := os.Getenv("EXCLUDE_NAMESPACES"); excludeList != "" {
		for _, ns := range strings.Split(excludeList, ",") {
			ns = strings.TrimSpace(ns)
			if ns != "" {
				nf.excludedNamespaces[ns] = true
			}
		}
		logrus.WithField("additional_excluded", excludeList).Info("Added additional excluded namespaces")
	}

	// INCLUDE_SYSTEM_NAMESPACES: if "true", don't exclude any namespaces by default
	if os.Getenv("INCLUDE_SYSTEM_NAMESPACES") == "true" {
		nf.excludedNamespaces = make(map[string]bool)
		logrus.Warn("System namespace filtering disabled - all namespaces will be monitored")
	}
}

// ShouldMonitor returns true if events from this namespace should be processed
func (nf *NamespaceFilter) ShouldMonitor(namespace string) bool {
	nf.mu.RLock()
	defer nf.mu.RUnlock()

	// Handle empty namespace (default namespace or unknown)
	if namespace == "" {
		namespace = "default"
	}

	// If using include mode, only monitor explicitly included namespaces
	if nf.useIncludeMode {
		return nf.includedNamespaces[namespace]
	}

	// Otherwise, exclude system namespaces
	return !nf.excludedNamespaces[namespace]
}

// AddExcludedNamespace adds a namespace to the exclude list
func (nf *NamespaceFilter) AddExcludedNamespace(namespace string) {
	nf.mu.Lock()
	defer nf.mu.Unlock()
	nf.excludedNamespaces[namespace] = true
}

// RemoveExcludedNamespace removes a namespace from the exclude list
func (nf *NamespaceFilter) RemoveExcludedNamespace(namespace string) {
	nf.mu.Lock()
	defer nf.mu.Unlock()
	delete(nf.excludedNamespaces, namespace)
}

// AddIncludedNamespace adds a namespace to the include list and enables include mode
func (nf *NamespaceFilter) AddIncludedNamespace(namespace string) {
	nf.mu.Lock()
	defer nf.mu.Unlock()
	nf.includedNamespaces[namespace] = true
	nf.useIncludeMode = true
}

// GetExcludedNamespaces returns the list of excluded namespaces
func (nf *NamespaceFilter) GetExcludedNamespaces() []string {
	nf.mu.RLock()
	defer nf.mu.RUnlock()

	result := make([]string, 0, len(nf.excludedNamespaces))
	for ns := range nf.excludedNamespaces {
		result = append(result, ns)
	}
	return result
}

// GetIncludedNamespaces returns the list of included namespaces
func (nf *NamespaceFilter) GetIncludedNamespaces() []string {
	nf.mu.RLock()
	defer nf.mu.RUnlock()

	result := make([]string, 0, len(nf.includedNamespaces))
	for ns := range nf.includedNamespaces {
		result = append(result, ns)
	}
	return result
}

// IsIncludeMode returns true if the filter is in include mode
func (nf *NamespaceFilter) IsIncludeMode() bool {
	nf.mu.RLock()
	defer nf.mu.RUnlock()
	return nf.useIncludeMode
}
