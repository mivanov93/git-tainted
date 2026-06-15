package model

// Transport is a remote's wire protocol.
type Transport string

const (
	TransportHTTPS Transport = "https"
	TransportSSH   Transport = "ssh"
)
