package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMakeJWT(t *testing.T) {
	userID, _ := uuid.Parse("be93db0d-4c6d-49cf-b56d-ba22392eb160")
	result, err := MakeJWT(userID, "secret", 1*time.Hour)
	if len(result) == 0 || err != nil {
		t.Errorf(`MakeJWT %s, %v, want "", error`, result, err)
	}
}

func TestGetBearerToken(t *testing.T) {
	headers := http.Header{}
	headers.Add("Authorization", "Bearer SomeSecretToken")
	token, err := GetBearerToken(headers)
	if err != nil || token != "SomeSecretToken" {
		t.Errorf(`GetBearerToken %s, %v, want "SomeSecretToken", error`, token, err)
	}
}

func TestGetBearerTokenMissingHeader(t *testing.T) {
	headers := http.Header{}
	token, err := GetBearerToken(headers)
	if err == nil || token != "" {
		t.Errorf(`GetBearerToken %s, %v, want "", error`, token, err)
	}
}

func TestGetBearerTokenMissingToken(t *testing.T) {
	headers := http.Header{}
	headers.Add("Authorization", "Bearer")
	token, err := GetBearerToken(headers)
	if err == nil || token != "" {
		t.Errorf(`GetBearerToken %s, %v, want "", error`, token, err)
	}
}
