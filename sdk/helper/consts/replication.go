package consts

// p22
type ReplicationState uint32

const (
	_ ReplicationState = iota
	OldReplicationPrimary
	OldReplicationSecondary
	OldReplicationBootstrapping

	ReplicationUnknown            ReplicationState = 0
	ReplicationPerformancePrimary ReplicationState = 1 << iota // Note -- iota is 5 here!
	ReplicationPerformanceSecondary
	OldSplitReplicationBootstrapping
	ReplicationDRPrimary
	ReplicationDRSecondary
	ReplicationPerformanceBootstrapping
	ReplicationDRBootstrapping
	ReplicationPerformanceDisabled
	ReplicationDRDisabled
	ReplicationPerformanceStandby
)

// p152
type HAState uint32

const (
	_ HAState = iota
	Standby
	PerfStandby
	Active
)
