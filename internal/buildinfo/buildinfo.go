// Package buildinfo exposes the binary's version string.
//
// `make build` injects the version via -ldflags:
//
//	-X github.com/mivanov93/git-tainted/internal/buildinfo.Version=$(git describe --tags --always --dirty)
//
// so a tagged build reports e.g. "v0.1.0", a few commits past a tag
// "v0.1.0-3-gabc1234", and a dirty tree "...-dirty". When the value is not
// injected (plain `go build`, `go run`, or `go install …@latest`), String()
// derives a version from the embedded VCS build info instead.
package buildinfo

import (
	"runtime/debug"
	"strings"
)

// Version is set at link time via -ldflags -X. Leave it empty by default so
// String() can fall back to the embedded build info.
var Version = ""

// String returns the build version. Precedence:
//  1. the -ldflags-injected Version (release / `make build`);
//  2. the module version from the build info (`go install …@v1.2.3`, or an
//     `@latest` pseudo-version like v0.0.0-20260616...-abc1234);
//  3. for a plain local build, "dev+<short-commit>[-dirty]" from VCS info;
//  4. "dev" if nothing is available.
func String() string {
	if v := strings.TrimSpace(Version); v != "" && v != "dev" {
		return v
	}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	if v := bi.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	var rev, dirty string
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "-dirty"
			}
		}
	}
	if rev != "" {
		if len(rev) > 12 {
			rev = rev[:12]
		}
		return "dev+" + rev + dirty
	}
	return "dev"
}
