package main

import (
	"strings"
	"testing"
)

func TestReadPipedPassword(t *testing.T) {
	// `echo pw | ...` appends a newline, `printf '%s' pw | ...` does not; both must yield
	// the same password.
	for _, in := range []string{"streng-geheim-123", "streng-geheim-123\n", "streng-geheim-123\r\n"} {
		got, err := readPipedPassword(strings.NewReader(in))
		if err != nil {
			t.Fatalf("readPipedPassword(%q): %v", in, err)
		}
		if got != "streng-geheim-123" {
			t.Errorf("readPipedPassword(%q) = %q", in, got)
		}
	}
	// Spaces inside the password are part of it and must survive.
	if got, _ := readPipedPassword(strings.NewReader("mit Leerzeichen \n")); got != "mit Leerzeichen " {
		t.Errorf("Leerzeichen am Ende verloren: %q", got)
	}
	if _, err := readPipedPassword(strings.NewReader("")); err == nil {
		t.Error("leere Eingabe wurde akzeptiert")
	}
	if _, err := readPipedPassword(strings.NewReader("\n")); err == nil {
		t.Error("nur ein Newline wurde als Passwort akzeptiert")
	}
}
