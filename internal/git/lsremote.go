package git

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"

	"github.com/mivanov93/git-tainted/internal/model"
)

const (
	prefixTags = "refs/tags/"
	peeledSfx  = "^{}"
)

// ParseLsRemote parses hardened `git ls-remote --tags` output into
// LsRemoteRefs, keeping only refs/tags/* (§6). Annotated tags produce ONE
// LsRemoteRef carrying both the tag-object oid (OID) and the peeled commit
// (PeeledOID), because ls-remote emits the peeled commit on a following
// `<name>^{}` line. algo fixes the expected oid width; a width mismatch is
// an error.
func ParseLsRemote(out []byte, algo model.HashAlgo) ([]model.LsRemoteRef, error) {
	if !algo.Valid() {
		return nil, fmt.Errorf("%w: invalid algo %q", model.ErrBadOID, algo)
	}
	var refs []model.LsRemoteRef
	// index of the last appended tag ref, for attaching a following peeled line.
	lastTagIdx := -1
	lastTagName := ""

	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		tab := strings.IndexByte(line, '\t')
		if tab < 0 {
			return nil, fmt.Errorf("ls-remote: malformed line (no tab): %q", line)
		}
		oidHex := line[:tab]
		fullRef := line[tab+1:]

		// Peeled line: refs/tags/<name>^{}
		if strings.HasSuffix(fullRef, peeledSfx) {
			base := strings.TrimSuffix(fullRef, peeledSfx)
			if !strings.HasPrefix(base, prefixTags) {
				continue
			}
			name := base[len(prefixTags):]
			if lastTagIdx < 0 || lastTagName != name {
				return nil, fmt.Errorf("ls-remote: dangling peeled line for %q (no preceding tag)", name)
			}
			peeled, err := model.ParseOID(oidHex, algo)
			if err != nil {
				return nil, fmt.Errorf("ls-remote: peeled oid for %q: %w", name, err)
			}
			refs[lastTagIdx].PeeledOID = peeled
			refs[lastTagIdx].IsAnnotatedTag = true
			continue
		}

		if !strings.HasPrefix(fullRef, prefixTags) {
			// HEAD, refs/heads/*, refs/pull/*, etc. — ignored (tags-only).
			continue
		}
		name := fullRef[len(prefixTags):]

		oid, err := model.ParseOID(oidHex, algo)
		if err != nil {
			return nil, fmt.Errorf("ls-remote: oid for %s: %w", fullRef, err)
		}
		refs = append(refs, model.LsRemoteRef{Name: model.RefName(name), OID: oid})
		lastTagIdx = len(refs) - 1
		lastTagName = name
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("ls-remote: scan: %w", err)
	}
	return refs, nil
}

// detectAlgoFromLsRemote infers the object format from the first oid's hex
// width: 40 → sha1, 64 → sha256. Returns "" if undetectable.
func detectAlgoFromLsRemote(out []byte) model.HashAlgo {
	for _, line := range bytes.Split(out, []byte{'\n'}) {
		tab := bytes.IndexByte(line, '\t')
		if tab <= 0 {
			continue
		}
		switch tab {
		case model.SHA1.HexLen():
			return model.SHA1
		case model.SHA256.HexLen():
			return model.SHA256
		}
	}
	return ""
}
