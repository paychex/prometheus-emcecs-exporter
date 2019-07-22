package collector

import (
	"math"
	"time"

	"github.com/paychex/prometheus-emcecs-exporter/pkg/ecsclient"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

// A EcsMeteringCollector implements the prometheus.Collector.
type EcsMeteringCollector struct {
	ecsClient *ecsclient.EcsClient
	namespace string
}

var (
	nameSpaceQuota = prometheus.NewDesc(
		prometheus.BuildFQName("emcecs", "metering", "namespacequota"),
		"quota information for namespace in KB",
		[]string{"ecsnamespace", "type"}, nil,
	)
	nameSpaceObjectTotal = prometheus.NewDesc(
		prometheus.BuildFQName("emcecs", "metering", "namespace_object_count"),
		"total count of objects in namespace",
		[]string{"ecsnamespace"}, nil,
	)
)

// NewEcsMeteringCollector returns an initialized Metering Collector.
func NewEcsMeteringCollector(emcecs *ecsclient.EcsClient, namespace string) (*EcsMeteringCollector, error) {

	log.Debugln("Init Metering exporter")
	return &EcsMeteringCollector{
		ecsClient: emcecs,
		namespace: namespace,
	}, nil
}

// Collect fetches the metering information such as quota and usage from the cluster
// It implements prometheus.Collector.
func (e *EcsMeteringCollector) Collect(ch chan<- prometheus.Metric) {
	log.Debugln("ECS Metering collect starting")
	if e.ecsClient == nil {
		log.Errorf("ECS client not configured.")
		return
	}
	start := time.Now()
	// create a function to go get a list of all namespaces
	nameSpaceReq := "https://" + e.ecsClient.ClusterAddress + ":4443/object/namespaces"
	n, err := e.ecsClient.CallECSAPI(nameSpaceReq)
	if err != nil {
		log.Errorf("Error getting metering info: %s", err)
		return
	}

	result := gjson.Get(n, "namespace.#.name")
	// We need to limit the number of requests going to the API at once
	// setting this to a max of 4 connections after some testing.
	// anything higher caused the ECS to get upset about to many api calls at once
	concurrency := 4
	sem := make(chan bool, concurrency)
	gb2kb := math.Pow10(6)

	for _, name := range result.Array() {
		// since we need this a few times, lets get the name once
		ns := name.String()

		// ensuring we don't overload the ECS with multiple calls, so we are limiting concurency to 4
		sem <- true
		go func() {
			defer func() { <-sem }()
			// retrieve the quota applied
			namespaceInfoReq := "https://" + e.ecsClient.ClusterAddress + ":4443/object/namespaces/namespace/" + ns + "/quota"
			n, err := e.ecsClient.CallECSAPI(namespaceInfoReq)
			if err != nil {
				log.Errorf("Error getting metering info quota: %s", err)
				return
			}
			if gjson.Get(n, "blockSize").Float() > 0 {
				ch <- prometheus.MustNewConstMetric(nameSpaceQuota, prometheus.GaugeValue, gjson.Get(n, "blockSize").Float()*gb2kb, ns, "block")
				ch <- prometheus.MustNewConstMetric(nameSpaceQuota, prometheus.GaugeValue, gjson.Get(n, "notificationSize").Float()*gb2kb, ns, "notification")
			}
			// retrieve the current metering info
			namespaceInfoReq = "https://" + e.ecsClient.ClusterAddress + ":4443/object/billing/namespace/" + ns + "/info?sizeunit=KB"
			n, err = e.ecsClient.CallECSAPI(namespaceInfoReq)
			if err != nil {
				log.Errorf("Error getting metering info quota: %s", err)
				return
			}
			ch <- prometheus.MustNewConstMetric(nameSpaceObjectTotal, prometheus.GaugeValue, gjson.Get(n, "total_objects").Float(), ns)
			ch <- prometheus.MustNewConstMetric(nameSpaceQuota, prometheus.GaugeValue, gjson.Get(n, "total_size").Float(), ns, "used")
		}()
	}
	// This ensures that all our go routines completed
	for i := 0; i < cap(sem); i++ {
		sem <- true
	}
	duration := float64(time.Since(start).Seconds())
	log.Infof("Scrape of metering took %f seconds for cluster %s\n", duration, e.ecsClient.ClusterAddress)
	log.Infoln("Metering exporter finished")
}

// Describe describes the metrics exported from this collector.
func (e *EcsMeteringCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- nameSpaceQuota
	ch <- nameSpaceObjectTotal
}
