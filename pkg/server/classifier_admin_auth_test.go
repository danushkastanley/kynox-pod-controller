package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClassifierAdminEndpointsFailClosedWithoutToken(t *testing.T) {
	api := &ClassifierAPI{server: &TelemetryServer{}}

	for _, handler := range []http.HandlerFunc{api.handleReloadRules, api.handleValidateRules} {
		request := httptest.NewRequest(http.MethodPost, "/", nil)
		response := httptest.NewRecorder()
		handler(response, request)

		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
		}
	}
}

func TestClassifierAdminEndpointsRequireCorrectBearerToken(t *testing.T) {
	api := &ClassifierAPI{server: &TelemetryServer{}, adminToken: "correct-secret"}

	for _, handler := range []http.HandlerFunc{api.handleReloadRules, api.handleValidateRules} {
		wrongRequest := httptest.NewRequest(http.MethodPost, "/", nil)
		wrongRequest.Header.Set("Authorization", "Bearer wrong-secret")
		wrongResponse := httptest.NewRecorder()
		handler(wrongResponse, wrongRequest)
		if wrongResponse.Code != http.StatusUnauthorized {
			t.Fatalf("wrong-token status = %d, want %d", wrongResponse.Code, http.StatusUnauthorized)
		}

		validRequest := httptest.NewRequest(http.MethodPost, "/", nil)
		validRequest.Header.Set("Authorization", "Bearer correct-secret")
		validResponse := httptest.NewRecorder()
		handler(validResponse, validRequest)
		if validResponse.Code != http.StatusBadRequest {
			t.Fatalf("valid-token status = %d, want downstream %d", validResponse.Code, http.StatusBadRequest)
		}
	}
}

func TestClassifierAdminEndpointsRejectDuplicateAuthorisationHeaders(t *testing.T) {
	api := &ClassifierAPI{server: &TelemetryServer{}, adminToken: "correct-secret"}
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.Header.Add("Authorization", "Bearer correct-secret")
	request.Header.Add("Authorization", "Bearer correct-secret")
	response := httptest.NewRecorder()

	api.handleReloadRules(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}
