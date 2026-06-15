package model

// Clock is the sole time source; injectable for deterministic tests. NowNS
// returns the current wall time as int64 unix-nanoseconds (the project's single
// time representation — never time.Time in domain types or the Store).
type Clock interface {
	// NowNS returns the current wall time as unix-nanoseconds.
	NowNS() int64
}
