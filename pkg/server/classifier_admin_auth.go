package server

import (
	"crypto/subtle"
	"net/http"
	"os"
	"strings"
)

const classifierAdminTokenEnv = "CLASSIFIER_ADMIN_TOKEN"

func loadClassifierAdminToken() string {
	return os.Getenv(classifierAdminTokenEnv)
}

func (api *ClassifierAPI) authorizeAdminRequest(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Cache-Control", "no-store")
	if api.adminToken == "" {
		http.Error(w, "Classifier administration is disabled", http.StatusServiceUnavailable)
		return false
	}

	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		writeBearerChallenge(w)
		return false
	}
	scheme, token, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.Contains(token, " ") {
		writeBearerChallenge(w)
		return false
	}
	if len(token) != len(api.adminToken) || subtle.ConstantTimeCompare([]byte(token), []byte(api.adminToken)) != 1 {
		writeBearerChallenge(w)
		return false
	}
	return true
}

func writeBearerChallenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="classifier-admin"`)
	http.Error(w, "Unauthorised", http.StatusUnauthorized)
}
