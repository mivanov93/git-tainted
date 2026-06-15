package model

import "testing"

func nilRemoteStore() RemoteStore           { return nil }
func nilRefStore() RefStore                 { return nil }
func nilObservationStore() ObservationStore { return nil }
func nilTaintStore() TaintStore             { return nil }
func nilStore() Store                       { return nil }

// compile-time assertions: the nil-returning helpers must satisfy each interface.
var (
	_ = nilRemoteStore()      //nolint:staticcheck
	_ = nilRefStore()         //nolint:staticcheck
	_ = nilObservationStore() //nolint:staticcheck
	_ = nilTaintStore()       //nolint:staticcheck
	_ = nilStore()            //nolint:staticcheck
)

func TestStoreSEAMDeclared(t *testing.T) { _ = t }
