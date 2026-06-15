package model

import (
	"context"
	"testing"
)

func nilClock() Clock { return nil }
func nilLock() Lock   { return nil }

func TestSeamInterfacesDeclared(t *testing.T) {
	//nolint:staticcheck // explicit type annotations are the compile-time assertion
	var (
		_ Clock = nilClock()
		_ Lock  = nilLock()
	)
	_ = context.Background()
}
