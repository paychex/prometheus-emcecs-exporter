package collector

import (
	"github.com/paychex/prometheus-emcecs-exporter/ecsclient"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
)

// A EcsReplCollector implements the prometheus.Collector.
type EcsReplCollector struct {
	ecsClient *ecsclient.EcsClient
	namespace string
}

var (
	replingresstraffic = prometheus.NewDesc(
		prometheus.BuildFQName("emcecs", "cluster", "replication_ingress_traffic"),
		"Replication ingress traffic in bytes/sec",
		[]string{"node"}, nil,
	)
	replegresstraffic = prometheus.NewDesc(
		prometheus.BuildFQName("emcecs", "cluster", "replication_egress_traffic"),
		"Replication egress traffic in bytes/sec",
		[]string{"node"}, nil,
	)
	chunkspendingreplication = prometheus.NewDesc(
		prometheus.BuildFQName("emcecs", "cluster", "data_replication_pending"),
		"Data awaiting replication in bytes",
		[]string{"node"}, nil,
	)
	journalpendingreplication = prometheus.NewDesc(
		prometheus.BuildFQName("emcecs", "cluster", "journal_replication_pending"),
		"Journal data awaiting replication in bytes",
		[]string{"node"}, nil,
	)
	chunkspendingxor = prometheus.NewDesc(
		prometheus.BuildFQName("emcecs", "cluster", "chunks_pending_xor"),
		"Number of chunks pending xor",
		[]string{"node"}, nil,
	)
	replicationtimestamp = prometheus.NewDesc(
		prometheus.BuildFQName("emcecs", "cluster", "last_replication_timestamp"),
		"Unix timestamp of last completed replication",
		[]string{"node"}, nil,
	)
)

// NewEcsReplCollector returns an initialized Cluster Replication Collector.
func NewEcsReplCollector(emcecs *ecsclient.EcsClient, namespace string) (*EcsReplCollector, error) {

	log.Debugln("Init exporter")
	return &EcsReplCollector{
		ecsClient: emcecs,
		namespace: namespace,
	}, nil
}

// Collect fetches the stats from configured ECS cluster as Prometheus metrics.
// It implements prometheus.Collector.
func (e *EcsReplCollector) Collect(ch chan<- prometheus.Metric) {
	log.Debugln("ECS Replication state collect starting")
	if e.ecsClient == nil {
		log.Errorf("ECS client not configured.")
		return
	}

	replState, err := e.ecsClient.RetrieveReplState()
	if err != nil {
		log.Error("Replication exporter received no info from array.")
		return
	}

	ch <- prometheus.MustNewConstMetric(replingresstraffic, prometheus.GaugeValue, replState.ReplicationIngressTraffic, replState.RgName)
	ch <- prometheus.MustNewConstMetric(replegresstraffic, prometheus.GaugeValue, replState.ReplicationEgressTraffic, replState.RgName)
	ch <- prometheus.MustNewConstMetric(chunkspendingreplication, prometheus.GaugeValue, replState.ChunksRepoPendingReplicationTotalSize, replState.RgName)
	ch <- prometheus.MustNewConstMetric(journalpendingreplication, prometheus.GaugeValue, replState.ChunksJournalPendingReplicationTotalSize, replState.RgName)
	ch <- prometheus.MustNewConstMetric(chunkspendingxor, prometheus.GaugeValue, replState.ChunksPendingXorTotalSize, replState.RgName)
	ch <- prometheus.MustNewConstMetric(replicationtimestamp, prometheus.CounterValue, replState.ReplicationRpoTimestamp, replState.RgName)

	log.Infoln("Replication exporter finished")
	log.Debugln(replState)
}

// Describe describes the metrics exported from this collector.
func (e *EcsReplCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- replingresstraffic
	ch <- replegresstraffic
	ch <- chunkspendingreplication
	ch <- journalpendingreplication
	ch <- chunkspendingxor
	ch <- replicationtimestamp
}
