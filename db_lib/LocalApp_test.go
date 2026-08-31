package db_lib

import (
	"os"
	"strings"
	"testing"

	"github.com/semaphoreui/semaphore/db"
	"github.com/semaphoreui/semaphore/util"
)

// contains checks if a slice contains a specific string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.HasPrefix(s, item) {
			return true
		}
	}
	return false
}

func TestGetEnvironmentVars(t *testing.T) {
	t.Setenv("SEMAPHORE_TEST", "test123")
	t.Setenv("SEMAPHORE_TEST2", "test222")
	t.Setenv("PASSWORD", "test222")
	t.Setenv("HTTP_PROXY", "http://proxy.corp:8080")
	t.Setenv("NO_PROXY", "localhost,.domain.com")
	t.Setenv("SSL_CERT_FILE", "/etc/ssl/certs/custom-ca.pem")

	util.Config = &util.ConfigType{
		ForwardedEnvVars: []string{"SEMAPHORE_TEST"},
		EnvVars: map[string]string{
			"ANSIBLE_FORCE_COLOR": "False",
		},
	}

	res := getEnvironmentVars()

	expectedSubstrings := []string{
		"SEMAPHORE_TEST=test123",
		"ANSIBLE_FORCE_COLOR=False",
		"PATH=",
		"HTTP_PROXY=http://proxy.corp:8080",
		"NO_PROXY=localhost,.domain.com",
		"SSL_CERT_FILE=/etc/ssl/certs/custom-ca.pem",
	}

	for _, e := range expectedSubstrings {
		if !contains(res, e) {
			t.Errorf("Expected result to contain %v, but got %v", e, res)
		}
	}

	// Unforwarded variables must not be leaked
	if contains(res, "PASSWORD=") {
		t.Errorf("PASSWORD should not be in environment variables, got %v", res)
	}
	if contains(res, "SEMAPHORE_TEST2=") {
		t.Errorf("SEMAPHORE_TEST2 should not be in environment variables without being in ForwardedEnvVars, got %v", res)
	}
}

func TestGetHomeDir(t *testing.T) {
	repo := db.Repository{
		ProjectID: 42,
	}
	templateID := 114

	// Set a known HOME value for testing
	originalHome := os.Getenv("HOME")
	testHome := "/home/testuser"
	os.Setenv("HOME", testHome) //nolint:errcheck
	defer os.Setenv("HOME", originalHome) //nolint:errcheck

	// Save original config and restore after all tests
	originalConfig := util.Config
	defer func() { util.Config = originalConfig }()

	tests := []struct {
		name         string
		homeDirMode  string
		tmpPath      string
		expectedHome string
		description  string
	}{
		{
			name:         "ProjectHome mode",
			homeDirMode:  util.HomeDirModeProjectHome,
			tmpPath:      "/tmp/semaphore",
			expectedHome: "/tmp/semaphore/project_42",
			description:  "Should return project temp directory",
		},
		{
			name:         "TemplateDir mode",
			homeDirMode:  util.HomeDirModeTemplateDir,
			tmpPath:      "/tmp/semaphore",
			expectedHome: testHome,
			description:  "Should return real user HOME",
		},
		{
			name:         "UserHome mode",
			homeDirMode:  util.HomeDirModeUserHome,
			tmpPath:      "/tmp/semaphore",
			expectedHome: testHome,
			description:  "Should return real user HOME",
		},
		{
			name:         "Empty/default mode",
			homeDirMode:  "",
			tmpPath:      "/tmp/semaphore",
			expectedHome: "",
			description:  "Should return empty string for unknown mode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup config for this test case
			util.Config = &util.ConfigType{
				HomeDirMode: tt.homeDirMode,
				TmpPath:     tt.tmpPath,
			}

			// Call getHomeDir
			result := getHomeDir(repo, templateID)

			// Verify the result
			if result != tt.expectedHome {
				t.Errorf("%s: expected HOME=%s, got HOME=%s",
					tt.description, tt.expectedHome, result)
			}
		})
	}
}
