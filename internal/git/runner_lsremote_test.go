package git_test

import (
	"context"
	"testing"
	"time"

	"github.com/mivanov93/git-tainted/internal/git"
	"github.com/mivanov93/git-tainted/internal/model"
	"github.com/mivanov93/git-tainted/internal/testutil"
)

func TestExecGitRunner_LsRemote_Fixture(t *testing.T) {
	srv := testutil.StartGitServer(t)
	const base = 1_700_000_000_000_000_000
	b := testutil.NewRepo(t, srv, "repo.git", model.SHA1)
	b.Commit("main", "c1", nil, base, base)
	b.Commit("main", "c2", []string{"c1"}, base+1, base+1)
	lightOID := b.LightweightTag("v1.0", "c1")
	annOID := b.AnnotatedTag("v2.0", "c2", "release 2.0", base+2)

	// Use http-allowlist runner so the loopback fixture server is reachable.
	runner := git.NewRunnerWithProtocols("git", 30*time.Second, "http:https:ssh")
	refs, err := runner.LsRemote(context.Background(), srv.URL("repo.git"), nil)
	if err != nil {
		t.Fatalf("LsRemote err = %v", err)
	}

	// Only tags should be returned (branches dropped).
	byName := map[string]model.LsRemoteRef{}
	for _, r := range refs {
		byName[r.Name] = r
	}

	// Branches must not appear.
	if _, ok := byName["main"]; ok {
		t.Errorf("branch main must not appear in tags-only ls-remote output")
	}

	light, ok := byName["v1.0"]
	if !ok || light.IsAnnotatedTag {
		t.Fatalf("lightweight tag v1.0 wrong: %+v", light)
	}
	if !light.OID.Equal(lightOID) {
		t.Errorf("v1.0 oid = %s want %s", light.OID.Hex(), lightOID.Hex())
	}

	ann, ok := byName["v2.0"]
	if !ok || !ann.IsAnnotatedTag {
		t.Fatalf("annotated tag v2.0 wrong: %+v", ann)
	}
	if !ann.OID.Equal(annOID) {
		t.Errorf("v2.0 tag-object oid = %s want %s", ann.OID.Hex(), annOID.Hex())
	}
	if ann.PeeledOID.IsZero() {
		t.Errorf("v2.0 peeled commit oid must be present for annotated tag")
	}
}
