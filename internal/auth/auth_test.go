package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	t.Run("should return API key when header is valid", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey my-secret-key")

		apiKey, err := GetAPIKey(headers)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if apiKey != "my-secret-key" {
			t.Fatalf("expected apiKey to be 'my-secret-key', got %v", apiKey)
		}
	})

	t.Run("should return error when no Authorization header is provided", func(t *testing.T) {
		headers := http.Header{}

		_, err := GetAPIKey(headers)
		if err == nil {
			t.Fatal("expected an error, got none")
		}

		if err != ErrNoAuthHeaderIncluded {
			t.Fatalf("expected error '%v', got '%v'", ErrNoAuthHeaderIncluded, err)
		}
	})

	t.Run("should return error for malformed Authorization header", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "Bearer my-secret-key")

		_, err := GetAPIKey(headers)
		if err == nil {
			t.Fatal("expected an error, got none")
		}

		expectedErr := "malformed authorization header"
		if err.Error() != expectedErr {
			t.Fatalf("expected error '%v', got '%v'", expectedErr, err)
		}
	})

	t.Run("should return error if Authorization header does not have a key", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey")

		_, err := GetAPIKey(headers)
		if err == nil {
			t.Fatal("expected an error, got none")
		}

		expectedErr := "malformed authorization header"
		if err.Error() != expectedErr {
			t.Fatalf("expected error '%v', got '%v'", expectedErr, err)
		}
	})
}
