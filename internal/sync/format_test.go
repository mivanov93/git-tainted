package sync

import (
	"testing"

	"github.com/mivanov93/git-tainted/internal/model"
)

func TestDetectObjectFormat(t *testing.T) {
	sha1Ref := model.LsRemoteRef{Name: "v1", OID: model.MustParseOID("1111111111111111111111111111111111111111", model.SHA1)}
	sha256Ref := model.LsRemoteRef{Name: "v1", OID: model.MustParseOID("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", model.SHA256)}

	tests := []struct {
		name    string
		refs    []model.LsRemoteRef
		want    model.HashAlgo
		wantErr bool
	}{
		{"sha1", []model.LsRemoteRef{sha1Ref}, model.SHA1, false},
		{"sha256", []model.LsRemoteRef{sha256Ref}, model.SHA256, false},
		{"empty_is_error", nil, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DetectObjectFormat(tc.refs)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("got=%q want=%q", got, tc.want)
			}
		})
	}
}
