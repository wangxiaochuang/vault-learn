package raft

import (
	"sync"
	"sync/atomic"
	"time"
)

// p119
type FollowerState struct {
	AppliedIndex    uint64
	LastHeartbeat   time.Time
	LastTerm        uint64
	IsDead          *atomic.Bool
	DesiredSuffrage string
	Version         string
	UpgradeVersion  string
	RedundancyZone  string
}

// p203
type FollowerStates struct {
	l         sync.RWMutex
	followers map[string]*FollowerState
}
