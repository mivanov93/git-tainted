package sync

import (
	"errors"

	"github.com/mivanov93/git-tainted/internal/model"
)

// ErrNoRefs is returned when object-format cannot be detected (no refs).
var ErrNoRefs = errors.New("sync: no refs to detect object format")

// DetectObjectFormat infers a remote's object format from the oid width of
// its ls-remote refs. All oids in a single ls-remote share a width.
func DetectObjectFormat(refs []model.LsRemoteRef) (model.HashAlgo, error) {
	for _, r := range refs {
		if !r.OID.IsZero() {
			return r.OID.Algo, nil
		}
	}
	return "", ErrNoRefs
}
