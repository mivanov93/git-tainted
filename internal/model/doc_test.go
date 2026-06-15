package model

import "testing"

func TestPackageDocPresent(t *testing.T) {
	if PackageName != "model" {
		t.Fatalf("PackageName = %q, want %q", PackageName, "model")
	}
}
