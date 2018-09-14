package collector

import (
	"github.com/paychex/prometheus-emcecs-exporter/ecsclient"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
)

// A EcsClusterCollector implements the prometheus.Collector.
type EcsClusterCollector struct {
	ecsClient *ecsclient.EcsClient
	namespace string
}

var (
	goodnodes = prometheus.NewDesc(
		prometheus.BuildFQName("emcecs", "cluster", "good_nodes"),
		"Current count of good nodes in cluster",
		[]string{"vdc"}, nil,
	)
	badnodes = prometheus.NewDesc(
		prometheus.BuildFQName("emcecs", "cluster", "bad_nodes"),
		"Current count of bad nodes in cluster",
		[]string{"vdc"}, nil,
	)

	gooddisk = prometheus.NewDesc(
		prometheus.BuildFQName("emcecs", "cluster", "good_disks"),
		"Current count of good disks in cluster",
		[]string{"vdc"}, nil,
	)
	baddisk = prometheus.NewDesc(
		prometheus.BuildFQName("emcecs", "cluster", "bad_disks"),
		"Current count of bad disks in cluster",
		[]string{"vdc"}, nil,
	)

	spacetotal = prometheus.NewDesc(
		prometheus.BuildFQName("emcecs", "cluster", "space_total"),
		"Cluster size in Bytes",
		[]string{"vdc"}, nil,
	)
	spacefree = prometheus.NewDesc(
		prometheus.BuildFQName("emcecs", "cluster", "space_free"),
		"Cluster space free in Bytes",
		[]string{"vdc"}, nil,
	)

	transactionerror = prometheus.NewDesc(
		prometheus.BuildFQName("emcecs", "cluster", "transaction_error"),
		"Count of transaction errors",
		[]string{"vdc"}, nil,
	)

	transactionsuccess = prometheus.NewDesc(
		prometheus.BuildFQName("emcecs", "cluster", "transaction_success"),
		"Count of transacation success",
		[]string{"vdc"}, nil,
	)

	transactionwlatency = prometheus.NewDesc(
		prometheus.BuildFQName("emcecs", "cluster", "transaction_write_latency"),
		"Transaction write latency in ms",
		[]string{"vdc"}, nil,
	)

	transactionrlatency = prometheus.NewDesc(
		prometheus.BuildFQName("emcecs", "cluster", "transaction_read_latency"),
		"Transaction read latency in ms",
		[]string{"vdc"}, nil,
	)

	transactionreadpersecond = prometheus.NewDesc(
		prometheus.BuildFQName("emcecs", "cluster", "transaction_read_per_second"),
		"Cluster transactions read in transactions per second",
		[]string{"vdc"}, nil,
	)

	transactionwritepersecond = prometheus.NewDesc(
		prometheus.BuildFQName("emcecs", "cluster", "transaction_write_per_second"),
		"Cluster transactions write in transactions per second",
		[]string{"vdc"}, nil,
	)

	transactionreadbandwidth = prometheus.NewDesc(
		prometheus.BuildFQName("emcecs", "cluster", "transaction_read_bandwidth"),
		"Cluster transaction read bandwidth in MB/S",
		[]string{"vdc"}, nil,
	)

	transactionwritebandwidth = prometheus.NewDesc(
		prometheus.BuildFQName("emcecs", "cluster", "transaction_write_bandwidth"),
		"Cluster transaction write bandwidth in MB/S",
		[]string{"vdc"}, nil,
	)

	alertsanumcritical = prometheus.NewDesc(
		prometheus.BuildFQName("emcecs", "cluster", "alerts_critical"),
		"Number of current critical alerts for the cluster",
		[]string{"vdc"}, nil,
	)

	alertsanumerror = prometheus.NewDesc(
		prometheus.BuildFQName("emcecs", "cluster", "alerts_error"),
		"Number of current error alerts for the cluster",
		[]string{"vdc"}, nil,
	)

	alertsanuminfo = prometheus.NewDesc(
		prometheus.BuildFQName("emcecs", "cluster", "alerts_info"),
		"Number of current info alerts for the cluster",
		[]string{"vdc"}, nil,
	)

	alertsanumwarning = prometheus.NewDesc(
		prometheus.BuildFQName("emcecs", "cluster", "alerts_warning"),
		"Number of current warning alerts for the cluster",
		[]string{"vdc"}, nil,
	)
)

// NewEcsClusterCollector returns an initialized Node DT Collector.
func NewEcsClusterCollector(emcecs *ecsclient.EcsClient, namespace string) (*EcsClusterCollector, error) {

	log.Debugln("Init exporter")
	return &EcsClusterCollector{
		ecsClient: emcecs,
		namespace: namespace,
	}, nil
}

// Collect fetches the stats from a ECS VDC and returns them as Prometheus metrics.
// It implements prometheus.Collector.
func (e *EcsClusterCollector) Collect(ch chan<- prometheus.Metric) {
	log.Debugln("ECS Cluster collect starting")
	if e.ecsClient == nil {
		log.Errorln("ECS client not configured.")
		return
	}

	fields := e.ecsClient.RetrieveClusterState()

	// fmt.Printf("TotalDTNum: %v, UnreadyNum: %v, UnKnownNum: %v, NodeIP: %v\n", node.TotalDTnum, node.UnreadyDTnum, node.UnknownDTnum, node.NodeIP)
	ch <- prometheus.MustNewConstMetric(transactionsuccess, prometheus.CounterValue, fields.TransactionSuccessTotal, fields.VdcName)
	ch <- prometheus.MustNewConstMetric(transactionerror, prometheus.CounterValue, fields.TransactionErrorsTotal, fields.VdcName)
	ch <- prometheus.MustNewConstMetric(goodnodes, prometheus.GaugeValue, fields.NumGoodNodes, fields.VdcName)
	ch <- prometheus.MustNewConstMetric(badnodes, prometheus.GaugeValue, fields.NumBadNodes, fields.VdcName)
	ch <- prometheus.MustNewConstMetric(gooddisk, prometheus.GaugeValue, fields.NumGoodDisks, fields.VdcName)
	ch <- prometheus.MustNewConstMetric(baddisk, prometheus.GaugeValue, fields.NumBadDisks, fields.VdcName)
	ch <- prometheus.MustNewConstMetric(spacefree, prometheus.GaugeValue, fields.DiskSpaceFree, fields.VdcName)
	ch <- prometheus.MustNewConstMetric(spacetotal, prometheus.GaugeValue, fields.DiskSpaceTotal, fields.VdcName)
	ch <- prometheus.MustNewConstMetric(transactionrlatency, prometheus.GaugeValue, fields.TransactionReadLatency, fields.VdcName)
	ch <- prometheus.MustNewConstMetric(transactionwlatency, prometheus.GaugeValue, fields.TransactionWriteLatency, fields.VdcName)
	ch <- prometheus.MustNewConstMetric(transactionreadpersecond, prometheus.GaugeValue, fields.TransactionReadTransactionsPerSecond, fields.VdcName)
	ch <- prometheus.MustNewConstMetric(transactionwritepersecond, prometheus.GaugeValue, fields.TransactionWriteTransactionsPerSecond, fields.VdcName)
	ch <- prometheus.MustNewConstMetric(transactionreadbandwidth, prometheus.GaugeValue, fields.TransactionReadBandwidthCurrent, fields.VdcName)
	ch <- prometheus.MustNewConstMetric(transactionwritebandwidth, prometheus.GaugeValue, fields.TransactionWriteBandwidthCurrent, fields.VdcName)

	// capture all alert counters
	ch <- prometheus.MustNewConstMetric(alertsanumcritical, prometheus.CounterValue, fields.AlertsNumUnackCritical, fields.VdcName)
	ch <- prometheus.MustNewConstMetric(alertsanumerror, prometheus.CounterValue, fields.AlertsNumUnackError, fields.VdcName)
	ch <- prometheus.MustNewConstMetric(alertsanuminfo, prometheus.CounterValue, fields.AlertsNumUnackInfo, fields.VdcName)
	ch <- prometheus.MustNewConstMetric(alertsanumwarning, prometheus.CounterValue, fields.AlertsNumUnackWarning, fields.VdcName)

	//log.Infof("Nodestate is exporter finished %v", nodeState)
	log.Infoln("Cluster exporter finished")
	log.Debugln(fields)
}

// Describe describes the metrics exported from this collector.
func (e *EcsClusterCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- transactionsuccess
	ch <- transactionerror
	ch <- goodnodes
	ch <- badnodes
	ch <- gooddisk
	ch <- baddisk
	ch <- spacefree
	ch <- spacetotal
	ch <- transactionrlatency
	ch <- transactionwlatency
	ch <- transactionreadpersecond
	ch <- transactionwritepersecond
	ch <- transactionreadbandwidth
	ch <- transactionwritebandwidth
	ch <- alertsanumcritical
	ch <- alertsanumerror
	ch <- alertsanuminfo
	ch <- alertsanumwarning
}
