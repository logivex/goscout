package portscan

type PortState string

const (
	StateOpen     PortState = "open"
	StateClosed   PortState = "closed"
	StateFiltered PortState = "filtered"
)

type Result struct {
	Port    int
	State   PortState
	Service string
}
