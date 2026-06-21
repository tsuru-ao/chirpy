package auth

import (
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
