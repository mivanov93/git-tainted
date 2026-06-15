// Package model holds git-tainted's domain types and the seam interfaces
// (Store, GitRunner, Lock, Clock). It is the dependency root: model imports
// nothing from internal/* so there are no import cycles; every implementation
// package depends on model, never the reverse.
//
// All timestamps are int64 unix-nanoseconds (field suffix NS). All object ids
// are raw bytes wrapped in OID and rendered as lowercase hex at the edges.
package model

// PackageName is a tracer constant.
const PackageName = "model"
