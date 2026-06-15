package testutil

import (
	"testing"

	"github.com/mivanov93/git-tainted/internal/model"
)

func TestRepoBuilder_LightweightAndAnnotatedTags(t *testing.T) {
	srv := StartGitServer(t)
	b := NewRepo(t, srv, "tagrepo", model.SHA1)

	base := b.Commit("main", "base", nil, 1_000_000_000_000, 1_000_000_000_000)
	_ = base

	// Lightweight tag — oid == commit oid.
	lwOID := b.LightweightTag("v0.1.0", "base")
	if lwOID.IsZero() {
		t.Fatal("lightweight tag oid is zero")
	}

	// Annotated tag — oid is the tag object, not the commit.
	annOID := b.AnnotatedTag("v1.0.0", "base", "release one", 2_000_000_000_000)
	if annOID.IsZero() {
		t.Fatal("annotated tag oid is zero")
	}

	// The two oids must be distinct (annotated creates a tag object).
	if lwOID.Hex() == annOID.Hex() {
		t.Fatalf("lightweight and annotated tag oids should differ, got %s", lwOID.Hex())
	}
}
