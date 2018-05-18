// Copyright 2018 Paychex Inc. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"net/http"
	"runtime"
	"strconv"
	"time"

	"github.com/paychex/prometheus-emcecs-exporter/collector"
	"github.com/paychex/prometheus-emcecs-exporter/config"
	"github.com/paychex/prometheus-emcecs-exporter/ecsclient"
	"github.com/paychex/prometheus-emcecs-exporter/version"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

const (
	namespace = "emc_ecs" // used for prometheus metrics
)

var (
	log        = logrus.New()
	debugLevel = flag.Bool("debug", false, "enable  debug messages")
	ecsURL     string
	config     *ecsconfig.Config

	// Metrics about the EMC ECS exporter itself.
	ecsCollectionDuration = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "emcecs_collection_duration_seconds",
			Help: "Duration of collections by the ECS exporter for type metering or perf",
		},
		[]string{"vdc", "type"},
	)
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
	ecsClusterInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "emcecs_cluster_version",
			Help: "A metric with a constant '1' value labeled by version, and nodecount",
		},
		[]string{"version", "nodecount"},
	)
)

func init() {
	log.Formatter = new(logrus.TextFormatter)

	if *debugLevel {
		log.Level = logrus.DebugLevel
		log.Debug("Setting logging to debug level.")
	} else {
		log.Info("Logging set to standard level.")
		log.Level = logrus.InfoLevel
	}

	//
	ecsCollectionBuildInfo.WithLabelValues(version.Release, version.Commit, runtime.Version()).Set(1)
	prometheus.MustRegister(ecsCollectionDuration)
	prometheus.MustRegister(ecsCollectionRequestErrors)
	prometheus.MustRegister(ecsCollectionBuildInfo)
	prometheus.MustRegister(ecsClusterInfo)

	// gather our configuration
	config = ecsconfig.GetConfig()
}

func queryHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "'target' parameter must be specified", 400)
		ecsCollectionRequestErrors.Inc()
		return
	}

	log.Debugf("Scraping target '%s'", target)

	start := time.Now()
	registry := prometheus.NewRegistry()

	c := ecsclient.EcsClient{
		UserName:       config.ECS.UserName,
		Password:       config.ECS.Password,
		ClusterAddress: target,
	}
	log.Info("Connecting to ECS Cluster: " + target)
	log.Debug("Retrieving ECS authToken")
	c.RetrieveAuthToken()

	// get our authtoken for future interactions

	c.RetrieveNodeInfo()
	log.Debug("ECS Cluster version is: " + c.EcsVersion)
	log.Debug("ECS Cluster node count: %v", c.RetrieveNodeCount())
	ecsClusterInfo.WithLabelValues(c.EcsVersion, strconv.Itoa(c.RetrieveNodeCount())).Set(1)

	if r.URL.Query().Get("metering") == "1" {
		// get just metering information
		meterExporter, err := collector.NewEcsMeteringCollector(&c, namespace)
		if err != nil {
			log.Fatalf("Can't create exporter : %s", err)
		}
		log.Debugln("Register Metering exporter")
		registry.MustRegister(meterExporter)
	} else {
		// get perf metrics
		// nodeexporter
		dtExporter, err := collector.NewEcsNodeDTCollector(&c, namespace)
		if err != nil {
			log.Fatalf("Can't create exporter : %s", err)
		}
		log.Debugln("Register node DT exporter")
		registry.MustRegister(dtExporter)
		clusterExporter, err := collector.NewEcsClusterCollector(&c, namespace)
		if err != nil {
			log.Fatalf("Can't create exporter : %s", err)
		}
		log.Debugln("Register cluster exporter")
		registry.MustRegister(clusterExporter)
		replExporter, err := collector.NewEcsReplCollector(&c, namespace)
		if err != nil {
			log.Fatalf("Can't create exporter : %s", err)
		}
		log.Debugln("Register Replication exporter")
		registry.MustRegister(replExporter)
	}

	// Delegate http serving to Promethues client library, which will call collector.Collect.
	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
	c.Logout()
	duration := float64(time.Since(start).Seconds())
	ecsCollectionRequestErrors.Add(c.ErrorCount)
	if r.URL.Query().Get("metering") == "1" {
		ecsCollectionDuration.WithLabelValues(target, "metering").Observe(duration)
	} else {
		ecsCollectionDuration.WithLabelValues(target, "perf").Observe(duration)
	}
	log.Debugf("Scrape of target '%s' took %f seconds", target, duration)
}

func main() {
	log.Info("Starting the ECS Exporter service...")
	log.Infof("commit: %s, build time: %s, release: %s",
		version.Commit, version.BuildTime, version.Release,
	)
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
	log.Info("Listening on port: ", listenPort)
	log.Fatal(http.ListenAndServe(listenPort, nil))
}
