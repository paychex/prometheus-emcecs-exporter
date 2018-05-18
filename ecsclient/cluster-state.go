package ecsclient

type EcsClusterState struct {
	NumBadDisks                           float64
	NumNodes                              float64
	NumBadNodes                           float64
	NumGoodDisks                          float64
	NumGoodNodes                          float64
	VdcName                               string
	AlertsNumUnackCritical                float64
	AlertsNumUnackError                   float64
	AlertsNumUnackInfo                    float64
	AlertsNumUnackWarning                 float64
	DiskSpaceFree                         float64
	DiskSpaceTotal                        float64
	DiskSpaceAllocated                    float64
	TransactionErrorsTotal                float64
	TransactionSuccessTotal               float64
	TransactionReadLatency                float64
	TransactionWriteLatency               float64
	TransactionReadTransactionsPerSecond  float64
	TransactionWriteTransactionsPerSecond float64
	TransactionWriteBandwidthCurrent      float64
	TransactionReadBandwidthCurrent       float64
}

type EcsReplState struct {
	RgName	string
	ReplicationIngressTraffic	float64
	ReplicationEgressTraffic float64
	ChunksRepoPendingReplicationTotalSize float64
	ChunksJournalPendingReplicationTotalSize float64
	ChunksPendingXorTotalSize float64
	ReplicationRpoTimestamp float64
}