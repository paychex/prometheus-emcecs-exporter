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
)

const (
	namespace = "emc_ecs" // used for prometheus metrics
)

var (
	log    = logrus.New()
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

	authTokenCache sync.Map
)

func init() {
	log.Formatter = new(logrus.TextFormatter)

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
		log.Info("'target' parameter must be specified")
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
		log.Infof("target: %s is not a valid host.\n error was: %v", target, err)
		ecsCollectionRequestErrors.Inc()
		ecsCollectionSuccess.WithLabelValues(target).Set(0)
		h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
		h.ServeHTTP(w, r)
		return
	}

	c := ecsclient.NewECSClient(config.ECS.UserName, config.ECS.Password, target)

	log.Info("Connecting to ECS Cluster: " + target)
	c.RetrieveNodeInfo()
	log.Debugf("ECS Cluster version is: %v", c.EcsVersion)
	log.Debugf("ECS Cluster node count: %v", c.RetrieveNodeCount())
	ecsClusterInfo.WithLabelValues(c.EcsVersion, strconv.Itoa(c.RetrieveNodeCount())).Set(1)

	// Need to get rid of the goto cheat.
	// replacing with a for loop, and ensureing it has backoff and
	// a short circuit
	lc := 1
	for lc < 4 {
		log.Debugf("Looking for cached Auth Token for %s", target)
		var ok bool
		result, ok := authTokenCache.Load(target)
		if !ok {
			log.Debug("Authtoken not found in cache.")
			log.Debugf("Retrieving ECS authToken for %s", target)
			// get our authtoken for future interactions
			a, err := c.RetrieveAuthToken()
			if err != nil {
				log.Debugf("Error getting auth token for %s", target)

				ecsCollectionRequestErrors.Inc()
				ecsCollectionSuccess.WithLabelValues(target).Set(0)
				h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
				h.ServeHTTP(w, r)
				return
			}
			authTokenCache.Store(target, a)
			result, _ := authTokenCache.Load(target)
			c.AuthToken = result.(string)
			ecsAuthCacheCounterMiss.Inc()
		} else {
			log.Debugf("Authtoken pulled from cache for %s", target)
			c.AuthToken = result.(string)
			ecsAuthCacheCounterHit.Inc()
		}

		// test to make sure that our auth token is good
		// if not delete it and loop back to our login logic above
		validateLoginURL := "https://" + c.ClusterAddress + ":4443/user/whoami"
		_, err = c.CallECSAPI(validateLoginURL)
		if err != nil {
			authTokenCache.Delete(target)
			log.Infof("Invalidating authToken for %s", target)
			lc += 1
		} else {
			// we have a valid auth token we can break out of this loop
			break
		}
	}
	if lc > 3 {
		// we looped and failed multiple times, so no need to go further
		log.Debugf("Error getting auth token for %s", target)

		ecsCollectionRequestErrors.Inc()
		ecsCollectionSuccess.WithLabelValues(target).Set(0)
		h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
		h.ServeHTTP(w, r)
		return
	}

	if r.URL.Query().Get("metering") == "1" {
		// get just metering information
		meterExporter, err := collector.NewEcsMeteringCollector(c, namespace)
		if err != nil {
			log.Infof("Can't create exporter : %s", err)
		}
		log.Debugln("Register Metering exporter")
		registry.MustRegister(meterExporter)
	} else {
		// get perf metrics
		// nodeexporter
		dtExporter, err := collector.NewEcsNodeDTCollector(c, namespace)
		if err != nil {
			log.Infof("Can't create exporter : %s", err)
		} else {
			log.Debugln("Register node DT exporter")
			registry.MustRegister(dtExporter)
		}
		clusterExporter, err := collector.NewEcsClusterCollector(c, namespace)
		if err != nil {
			log.Infof("Can't create exporter : %s", err)
		} else {
			log.Debugln("Register cluster exporter")
			registry.MustRegister(clusterExporter)
		}
		replExporter, err := collector.NewEcsReplCollector(c, namespace)
		if err != nil {
			log.Infof("Can't create exporter : %s", err)
		} else {
			log.Debugln("Register Replication exporter")
			registry.MustRegister(replExporter)
		}
	}

	// Delegate http serving to Promethues client library, which will call collector.Collect.
	ecsCollectionRequestErrors.Add(c.ErrorCount)
	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}

func fullLogout() {
	//We have been asked to shut down, lets not leave any auth tokens active
	log.Info("Logging out of all arrays.")
	authTokenCache.Range(func(k, v interface{}) bool {
		log.Debugf("Logging out of array: %v", k)
		c := ecsclient.EcsClient{
			UserName:       config.ECS.UserName,
			Password:       config.ECS.Password,
			ClusterAddress: k.(string),
			AuthToken:      v.(string),
		}
		err := c.Logout()
		if err != nil {
			log.Debugf("Failed to log out of array: %v", k)
		}
		return true
	})
}

func main() {

	if config.Exporter.Debug {
		log.Level = logrus.DebugLevel
		log.Debug("Setting logging to debug level.")
	} else {
		log.Info("Logging set to standard level.")
		log.Level = logrus.InfoLevel
	}

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
		log.Infof("Signal (%v) Detected, Shutting Down", sig)
		fullLogout()
		os.Exit(2)
	}()

	log.Info("Starting the ECS Exporter service...")
	log.Infof("commit: %s, build time: %s, release: %s",
		commit, date, version,
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
