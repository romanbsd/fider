package web_test

import (
	"testing"

	"github.com/getfider/fider/app/pkg/web"
)

func TestBearerToken(t *testing.T) {
	token, err := web.BearerToken("Bearer abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "abc123" {
		t.Fatalf("expected abc123, got %s", token)
	}
}

func TestBearerToken_TrimSpaces(t *testing.T) {
	token, err := web.BearerToken("  Bearer   abc123  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "abc123" {
		t.Fatalf("expected abc123, got %s", token)
	}
}

func TestBearerToken_Invalid(t *testing.T) {
	if _, err := web.BearerToken(""); err == nil {
		t.Fatal("expected error for empty header")
	}
	if _, err := web.BearerToken("NotABearerHeader"); err == nil {
		t.Fatal("expected error for non-bearer header")
	}
	if _, err := web.BearerToken("Bearer"); err == nil {
		t.Fatal("expected error for empty token")
	}
}