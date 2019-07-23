// Copyright 2018 Paychex Inc. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"syscall"

	"github.com/paychex/prometheus-emcecs-exporter/pkg/collector"
	ecsconfig "github.com/paychex/prometheus-emcecs-exporter/pkg/config"
	"github.com/paychex/prometheus-emcecs-exporter/pkg/ecsclient"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

const (
	namespace = "emc_ecs" // used for prometheus metrics
)

var (
	ecsURL string
	config *ecsconfig.Config

	// date is a time label of the moment when the binary was built
	date = "unset"
	// commit is a last commit hash at the moment when the binary was built
	commit = "unset"
	// version is a semantic version of current build
	version = "unset"

	// Metrics about the EMC ECS exporter itself.
	ecsCollectionRequestErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "emcecs_request_errors_total",
			Help: "Total errors in requests to the ECS exporter",
		},
	)

	ecsCollectionBuildInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "emcecs_collector_build_info",
			Help: "A metric with a constant '1' value labeled by version, commitid and goversion exporter was built",
		},
		[]string{"version", "commitid", "goversion"},
	)

	ecsAuthCacheCounterHit = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "emcecs_authtoken_cache_counter_hit",
			Help: "count of authtoken cache hits",
		},
	)

	ecsAuthCacheCounterMiss = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "emcecs_authtoken_cache_counter_miss",
			Help: "count of authtoken cache misses",
		},
	)

	clientCache sync.Map
)

func init() {
	customFormatter := new(logrus.TextFormatter)
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	customFormatter.FullTimestamp = true

	log.SetFormatter(customFormatter)

	//
	ecsCollectionBuildInfo.WithLabelValues(version, commit, runtime.Version()).Set(1)
	prometheus.MustRegister(ecsCollectionBuildInfo)
	prometheus.MustRegister(ecsAuthCacheCounterHit)
	prometheus.MustRegister(ecsAuthCacheCounterMiss)

	// gather our configuration
	config = ecsconfig.GetConfig()

}

func queryHandler(w http.ResponseWriter, r *http.Request) {

	ecsCollectionSuccess := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "emcecs_collection_success",
			Help: "returns either 1 or 0 depending on success labeled by target_name",
		},
		[]string{"target_name"},
	)

	ecsClusterInfo := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "emcecs_cluster_version",
			Help: "A metric with a constant '1' value labeled by version, and nodecount",
		},
		[]string{"version", "nodecount"},
	)

	// some initial things we need before we get going.
	registry := prometheus.NewRegistry()
	registry.MustRegister(ecsCollectionBuildInfo)
	registry.MustRegister(ecsClusterInfo)
	registry.MustRegister(ecsCollectionRequestErrors)
	registry.MustRegister(ecsCollectionSuccess)

	target := r.URL.Query().Get("target")
	if target == "" {
		log.WithFields(log.Fields{"package": "main"}).Error("'target' parameter must be specified")
		log.WithFields(log.Fields{"package": "main"}).Error("incrementing requests errors by 1")
		ecsCollectionRequestErrors.Inc()
		ecsCollectionSuccess.WithLabelValues("NULL").Set(0)
		h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
		h.ServeHTTP(w, r)
		return
	}

	// assume success if we fail anywhere along the line, change this to 0
	ecsCollectionSuccess.WithLabelValues(target).Set(1)

	// Check and make sure we have a valid dns name, if not dump and run now.
	_, err := net.LookupHost(target)
	if err != nil {
		log.WithFields(log.Fields{"package": "main", "cluster": target}).Errorf("Cluster is not a valid host. Error was: %v", err)
		log.WithFields(log.Fields{"package": "main"}).Error("incrementing requests errors by 1")
		ecsCollectionRequestErrors.Inc()
		ecsCollectionSuccess.WithLabelValues(target).Set(0)
		h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
		h.ServeHTTP(w, r)
		return
	}

	// look to see if we have a ECS client already defined for this target
	var ok bool
	var result interface{}
	result, ok = clientCache.Load(target)
	if !ok {
		// We did not have a client cached. We need to create one and store it
		log.WithFields(log.Fields{"package": "main", "cluster": target}).Debug("Creating new ECS Client.")
		c := ecsclient.NewECSClient(target, config)

		err := c.Login()
		if err != nil {
			log.WithFields(log.Fields{"package": "main", "cluster": target}).Errorf("Could not log into cluster, the error was %s", err)
			log.WithFields(log.Fields{"package": "main"}).Error("incrementing requests errors by 1")
			ecsCollectionRequestErrors.Inc()
			ecsCollectionSuccess.WithLabelValues(target).Set(0)
			h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
			h.ServeHTTP(w, r)
			return
		}
		clientCache.Store(target, c)
		result, _ = clientCache.Load(target)
	}

	c := result.(*ecsclient.EcsClient)

	c.RetrieveNodeInfoV2()
	log.WithFields(log.Fields{"package": "main", "cluster_version": c.EcsVersion, "node_count": c.RetrieveNodeCount()}).Debugf("ECS Cluster Info.")
	ecsClusterInfo.WithLabelValues(c.EcsVersion, strconv.Itoa(c.RetrieveNodeCount())).Set(1)

	if r.URL.Query().Get("metering") == "1" {
		// get just metering information
		meterExporter, err := collector.NewEcsMeteringCollector(c, namespace)
		if err != nil {
			log.WithFields(log.Fields{"package": "main"}).Errorf("Can't create exporter : %s", err)
		}
		log.WithFields(log.Fields{"package": "main"}).Debug("Register Metering exporter")
		registry.MustRegister(meterExporter)
	} else {
		// get perf metrics
		// nodeexporter
		dtExporter, err := collector.NewEcsNodeDTCollector(c, namespace)
		if err != nil {
			log.WithFields(log.Fields{"package": "main"}).Errorf("Can't create exporter : %s", err)
		} else {
			log.WithFields(log.Fields{"package": "main"}).Debug("Register node DT exporter")
			registry.MustRegister(dtExporter)
		}
		clusterExporter, err := collector.NewEcsClusterCollector(c, namespace)
		if err != nil {
			log.WithFields(log.Fields{"package": "main"}).Errorf("Can't create exporter : %s", err)
		} else {
			log.WithFields(log.Fields{"package": "main"}).Debug("Register cluster exporter")
			registry.MustRegister(clusterExporter)
		}
		replExporter, err := collector.NewEcsReplCollector(c, namespace)
		if err != nil {
			log.WithFields(log.Fields{"package": "main"}).Errorf("Can't create exporter : %s", err)
		} else {
			log.WithFields(log.Fields{"package": "main"}).Debug("Register Replication exporter")
			registry.MustRegister(replExporter)
		}
	}

	// Delegate http serving to Promethues client library, which will call collector.Collect.
	log.WithFields(log.Fields{"package": "main"}).Debugf("incrementing requests errors by %v\n", c.ErrorCount)
	ecsCollectionRequestErrors.Add(float64(c.ErrorCount))
	// we have recorded this round of errors zero out the errorCount before moving on
	c.ZeroErrorCount()
	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}

func fullLogout() {
	//We have been asked to shut down, lets not leave any auth tokens active
	log.WithFields(log.Fields{"package": "main"}).Info("Logging out of all clusters.")
	clientCache.Range(func(k, v interface{}) bool {
		log.WithFields(log.Fields{"package": "main", "cluster": k}).Debug("Logging out of cluster.")
		c := v.(*ecsclient.EcsClient)
		err := c.Logout()
		if err != nil {
			log.WithFields(log.Fields{"package": "main", "cluster": k}).Debug("Failed to log out of cluster.")
		}
		return true
	})
}

func main() {

	if config.Exporter.Debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	log.WithFields(log.Fields{"package": "main", "loglevel": log.GetLevel()}).Info("Logging level set.")

	// enable signal trapping to ensure clean shutdown
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c,
			syscall.SIGINT,  // Ctrl+C
			syscall.SIGTERM, // Termination Request
			syscall.SIGSEGV, // Segmentation Fault
			syscall.SIGABRT, // Abnormal termination
			syscall.SIGILL,  // illegal instruction
			syscall.SIGFPE)  // floating point
		sig := <-c
		log.WithFields(log.Fields{"package": "main", "signal": sig}).Info("OS Signal Detected, Shutting Down")
		fullLogout()
		os.Exit(2)
	}()

	log.WithFields(log.Fields{"package": "main", "commit": commit, "date": date, "version": version}).Info("Starting the ECS Exporter service...")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
            <head>
            <title>ECS Cluster Exporter</title>
            <style>
            label{
            display:inline-block;
            width:75px;
            }
            form label {
            margin: 10px;
            }
            form input {
            margin: 10px;
            }
            </style>
            </head>
            <body>
            <h1>Cluster Exporter</h1>
            <form action="/query">
            <label>Target:</label> <input type="text" name="target" placeholder="X.X.X.X" value="1.2.3.4"><br>
            <input type="submit" value="Submit">
            </form>
            </html>`))
	})

	http.HandleFunc("/query", queryHandler)     // Endpoint to do specific cluster scrapes.
	http.Handle("/metrics", promhttp.Handler()) // endpoint for exporter stats
	listenPort := fmt.Sprintf(":%v", config.Exporter.BindPort)
	log.WithFields(log.Fields{"package": "main", "port": listenPort}).Info("HTTP Service running.")
	log.WithFields(log.Fields{"package": "main"}).Fatal(http.ListenAndServe(listenPort, nil))
}
