package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

// ClassifierAPI provides HTTP endpoints for classifier management
type ClassifierAPI struct {
	server *TelemetryServer
}

// NewClassifierAPI creates a new classifier API
func NewClassifierAPI(server *TelemetryServer) *ClassifierAPI {
	return &ClassifierAPI{
		server: server,
	}
}

// RegisterRoutes registers all classifier management routes
func (api *ClassifierAPI) RegisterRoutes(mux *http.ServeMux) {
	// Rule management endpoints
	mux.HandleFunc("/api/v1/classifier/rules", api.handleRules)
	mux.HandleFunc("/api/v1/classifier/rules/reload", api.handleReloadRules)
	mux.HandleFunc("/api/v1/classifier/rules/validate", api.handleValidateRules)

	// Metrics and monitoring endpoints
	mux.HandleFunc("/api/v1/classifier/metrics", api.handleMetrics)
	mux.HandleFunc("/api/v1/classifier/metrics/summary", api.handleMetricsSummary)
	mux.HandleFunc("/api/v1/classifier/status", api.handleStatus)

	// Configuration endpoints
	mux.HandleFunc("/api/v1/classifier/config", api.handleConfig)
	mux.HandleFunc("/api/v1/classifier/health", api.handleHealth)
}

// handleRules manages rule information
func (api *ClassifierAPI) handleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		api.getRulesInfo(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleReloadRules handles rule hot-reload
func (api *ClassifierAPI) handleReloadRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Type assert to get the enhanced classifier
	enhancedClassifier, ok := api.server.classifier.(*EnhancedYAMLClassifier)
	if !ok {
		http.Error(w, "Hot reload not supported by current classifier", http.StatusBadRequest)
		logrus.Error("Attempted hot reload on non-enhanced classifier")
		return
	}

	logrus.Info("Hot reload requested via API")

	if err := enhancedClassifier.ReloadRules(); err != nil {
		logrus.WithError(err).Error("Rule hot reload failed")
		api.writeErrorResponse(w, http.StatusInternalServerError, "Rule reload failed", err)
		return
	}

	response := map[string]interface{}{
		"success":   true,
		"message":   "Rules reloaded successfully",
		"timestamp": time.Now().Format(time.RFC3339),
	}

	api.writeJSONResponse(w, http.StatusOK, response)
	logrus.Info("Rules hot-reloaded successfully via API")
}

// handleValidateRules validates current rules
func (api *ClassifierAPI) handleValidateRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	enhancedClassifier, ok := api.server.classifier.(*EnhancedYAMLClassifier)
	if !ok {
		http.Error(w, "Rule validation not supported by current classifier", http.StatusBadRequest)
		return
	}

	if err := enhancedClassifier.ValidateRules(); err != nil {
		logrus.WithError(err).Warn("Rule validation failed")
		api.writeErrorResponse(w, http.StatusBadRequest, "Rule validation failed", err)
		return
	}

	response := map[string]interface{}{
		"success":   true,
		"message":   "All rules are valid",
		"timestamp": time.Now().Format(time.RFC3339),
	}

	api.writeJSONResponse(w, http.StatusOK, response)
}

// handleMetrics returns detailed metrics
func (api *ClassifierAPI) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	enhancedClassifier, ok := api.server.classifier.(*EnhancedYAMLClassifier)
	if !ok {
		http.Error(w, "Metrics not supported by current classifier", http.StatusBadRequest)
		return
	}

	metrics := enhancedClassifier.GetMetrics()
	api.writeJSONResponse(w, http.StatusOK, metrics)
}

// handleMetricsSummary returns concise metrics summary
func (api *ClassifierAPI) handleMetricsSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	enhancedClassifier, ok := api.server.classifier.(*EnhancedYAMLClassifier)
	if !ok {
		http.Error(w, "Metrics not supported by current classifier", http.StatusBadRequest)
		return
	}

	summary := enhancedClassifier.metrics.GetSummary()
	api.writeJSONResponse(w, http.StatusOK, summary)
}

// handleStatus returns classifier status
func (api *ClassifierAPI) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	enhancedClassifier, ok := api.server.classifier.(*EnhancedYAMLClassifier)
	if !ok {
		status := map[string]interface{}{
			"classifier_type":   "basic",
			"advanced_features": false,
			"timestamp":         time.Now().Format(time.RFC3339),
		}
		api.writeJSONResponse(w, http.StatusOK, status)
		return
	}

	rulesInfo := enhancedClassifier.GetRulesInfo()
	status := map[string]interface{}{
		"classifier_type":    "enhanced_yaml",
		"advanced_features":  true,
		"hot_reload_enabled": enhancedClassifier.config.EnableHotReload,
		"metrics_enabled":    enhancedClassifier.config.MetricsEnabled,
		"validation_enabled": enhancedClassifier.config.ValidateRules,
		"rules_info":         rulesInfo,
		"timestamp":          time.Now().Format(time.RFC3339),
	}

	api.writeJSONResponse(w, http.StatusOK, status)
}

// handleConfig returns classifier configuration
func (api *ClassifierAPI) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	enhancedClassifier, ok := api.server.classifier.(*EnhancedYAMLClassifier)
	if !ok {
		config := map[string]interface{}{
			"classifier_type": "basic",
			"message":         "Advanced configuration not available",
		}
		api.writeJSONResponse(w, http.StatusOK, config)
		return
	}

	config := map[string]interface{}{
		"rules_path":      enhancedClassifier.config.RulesPath,
		"hot_reload":      enhancedClassifier.config.EnableHotReload,
		"validation":      enhancedClassifier.config.ValidateRules,
		"metrics":         enhancedClassifier.config.MetricsEnabled,
		"classifier_type": "enhanced_yaml",
		"timestamp":       time.Now().Format(time.RFC3339),
	}

	api.writeJSONResponse(w, http.StatusOK, config)
}

// handleHealth provides health check endpoint
func (api *ClassifierAPI) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
		"uptime":    time.Since(api.server.getStartTime()).String(),
	}

	// Add classifier-specific health information
	if enhancedClassifier, ok := api.server.classifier.(*EnhancedYAMLClassifier); ok {
		metrics := enhancedClassifier.metrics.GetSummary()
		health["classifier"] = map[string]interface{}{
			"type":               "enhanced_yaml",
			"events_processed":   metrics["total_events"],
			"error_rate_percent": metrics["error_rate_percent"],
			"avg_response_time":  fmt.Sprintf("%.2fms", metrics["avg_classification_time_ms"]),
		}
	}

	api.writeJSONResponse(w, http.StatusOK, health)
}

// getRulesInfo returns comprehensive rule information
func (api *ClassifierAPI) getRulesInfo(w http.ResponseWriter, r *http.Request) {
	enhancedClassifier, ok := api.server.classifier.(*EnhancedYAMLClassifier)
	if !ok {
		info := map[string]interface{}{
			"classifier_type": "basic",
			"message":         "Rule information not available for basic classifier",
		}
		api.writeJSONResponse(w, http.StatusOK, info)
		return
	}

	rulesInfo := enhancedClassifier.GetRulesInfo()
	api.writeJSONResponse(w, http.StatusOK, rulesInfo)
}

// Utility methods

func (api *ClassifierAPI) writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		logrus.WithError(err).Error("Failed to encode JSON response")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func (api *ClassifierAPI) writeErrorResponse(w http.ResponseWriter, statusCode int, message string, err error) {
	response := map[string]interface{}{
		"success":   false,
		"message":   message,
		"error":     err.Error(),
		"timestamp": time.Now().Format(time.RFC3339),
	}

	api.writeJSONResponse(w, statusCode, response)
}

// getStartTime returns when the server was started
func (s *TelemetryServer) getStartTime() time.Time {
	return s.startTime
}
