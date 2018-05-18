package collector

import (
	"github.com/paychex/prometheus-emcecs-exporter/ecsclient"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
)

// A EcsNodeDTCollector implements the prometheus.Collector.
type EcsNodeDTCollector struct {
	ecsClient *ecsclient.EcsClient
	namespace string
}

var (
	dtTotal = prometheus.NewDesc(
		prometheus.BuildFQName("emcecs", "node", "dtTotal"),
		"Total number of DTs on node",
		[]string{"node"}, nil,
	)
	dtUnready = prometheus.NewDesc(
		prometheus.BuildFQName("emcecs", "node", "dtUnready"),
		"Number of dt in unready state on node",
		[]string{"node"}, nil,
	)
	dtUnknown = prometheus.NewDesc(
		prometheus.BuildFQName("emcecs", "node", "dtUnknown"),
		"Number of dt in unknown state on node",
		[]string{"node"}, nil,
	)
	activeConnections = prometheus.NewDesc(
		prometheus.BuildFQName("emcecs", "node", "activeConnections"),
		"Number of current active connections on node",
		[]string{"node"}, nil,
	)
)

// NewEcsNodeDTCollector returns an initialized Node DT Collector.
func NewEcsNodeDTCollector(emcecs *ecsclient.EcsClient, namespace string) (*EcsNodeDTCollector, error) {

	log.Debugln("Init exporter")
	return &EcsNodeDTCollector{
		ecsClient: emcecs,
		namespace: namespace,
	}, nil
}

// Collect fetches the stats from configured nodes as Prometheus metrics.
// It implements prometheus.Collector.
func (e *EcsNodeDTCollector) Collect(ch chan<- prometheus.Metric) {
	log.Debugln("ECS Node DT collect starting")
	if e.ecsClient == nil {
		log.Errorf("ECS client not configured.")
		return
	}

	nodeState := e.ecsClient.RetrieveNodeStateParallel()
	for _, node := range nodeState {
		// fmt.Printf("TotalDTNum: %v, UnreadyNum: %v, UnKnownNum: %v, NodeIP: %v\n", node.TotalDTnum, node.UnreadyDTnum, node.UnknownDTnum, node.NodeIP)
		ch <- prometheus.MustNewConstMetric(dtTotal, prometheus.GaugeValue, node.TotalDTnum, node.NodeIP)
		ch <- prometheus.MustNewConstMetric(dtUnready, prometheus.GaugeValue, node.UnreadyDTnum, node.NodeIP)
		ch <- prometheus.MustNewConstMetric(dtUnknown, prometheus.GaugeValue, node.UnknownDTnum, node.NodeIP)
		ch <- prometheus.MustNewConstMetric(activeConnections, prometheus.GaugeValue, node.ActiveConnections, node.NodeIP)
	}

	log.Infoln("Nodestate exporter finished")
	log.Debugln(nodeState)
}

// Describe describes the metrics exported from this collector.
func (e *EcsNodeDTCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- dtTotal
	ch <- dtUnready
	ch <- dtUnknown
	ch <- activeConnections
}
