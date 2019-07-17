# Prometheus exporter for EMC ECS

[![Build Status](https://api.travis-ci.com/paychex/prometheus-emcecs-exporter.svg?branch=master)](https://travis-ci.com/paychex/prometheus-emcecs-exporter/builds)
[![Go Report Card](https://goreportcard.com/badge/github.com/paychex/prometheus-emcecs-exporter)](https://goreportcard.com/report/github.com/paychex/prometheus-emcecs-exporter)

This exporter collects performance and metrics stats from Dell EMC ECS clusters running version 3.x and above and makes it available for Prometheus to scrape. It is not recommended that you run this tool on the Dell EMC ECS Cluster node(s), instead it should be run on a separate machine. The application can be configured to monitor just one cluster, or can be configured to query multiple Dell EMC ECS clusters. See configuration options below for how to use this tool.

## Usage

| Flag         | Description                                            | Default Value | Env Name            |
| ------------ | ------------------------------------------------------ | ------------- | ------------------- |
| username     | Username with which to connect to the Dell EMC ECS API | none          | ECSENV_USERNAME     |
| password     | Password with which to connect to the Dell EMC ECS API | none          | ECSENV_PASSWORD     |
| mgmt_port    | The port which ecs listens to for administration       | 4443          | ECSENV_MGMT_PORT    |
| obj_port     | The port which ecs listens to for object calls         | 9021          | ECSENV_OBJ_PORT     |
| bind_port    | Port to bind the exporter endpoint to                  | 9438          | ECSENV_BIND_PORT    |
| bind_address | Address to bind the exporter endpoint to               | localhost     | ECSENV_BIND_ADDRESS |
| debug        | Enable verbose debugging messages                      | false         | ECSENV_DEBUG        |

### Port Requirements

The following ports need to be open between the ECS array and the exporter:

* 9101
* 9021
* 4443

### Running in multi-query mode

While normally one runs one exporter per device, this exporter works a little different. The exporter is designed to work by default in a "multi-query" mode. This setup works similar to the [SNMP exporter](https://github.com/prometheus/snmp_exporter).  Note that you will need to configure each ECS cluster to use the same username and password for this to work properly. You can still monitor just one array if you so choose, its just a few extra lines in your Prometheus config file.

When configuring Prometheus to scrape in this manner use the following Prometheus config snippet:

````YAML
scrape_configs:
  - job_name: 'emcecs'
    static_configs:
      - targets:
        - myecsarray-1.net  # EMC ECS Cluster/VDC
        - myecsarray-2.net  # EMC ECS Cluster/VDC
        - myecsarray-3.net  # EMC ECS Cluster/VDC
    metrics_path: /query
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:9438  # The EMC ECS exporter's real hostname:port running in "multi-query" mode
  - job_name: 'emcecs-exporter-stats' # gathers the exporter application process stats if you want this sort of information
    static_configs:
      - targets: 127.0.0.1:9438
  # this monitors emc ecs clusters for quota usage.  only have to do it every so often, and only need to query the cluster itself
  - job_name: 'ecs_quota'
    scrape_interval:    300s
    scrape_timeout:     60s
    params:
      metering: ["1"]
    metrics_path: /query
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:9438  # ECS exporter.
    static_configs:
      - targets: ['myecsarray-1.net','myecsarray-2.net']
````

## Exported Metrics

This exporter exports information in two ways. The first is a standard export of performance and system health stats.  Additionally you can get an export of metering metrics (for now just quota usage/space usage). This is done by specifying an additional option "metering=1" on the query and you will get back a set of stats on namespace usage. This query can take a long time, and does not need to be done at quite as high a frequency as performance stats. It is suggested polling this on a 5 minute or higher frequency due to the rate of change being much lower in most cases.

### Dell EMC ECS Performance Stats

````
# HELP emcecs_cluster_alerts_critical Number of current critical alerts for the cluster
# TYPE emcecs_cluster_alerts_critical counter
# HELP emcecs_cluster_alerts_error Number of current error alerts for the cluster
# TYPE emcecs_cluster_alerts_error counter
# HELP emcecs_cluster_alerts_info Number of current info alerts for the cluster
# TYPE emcecs_cluster_alerts_info counter
# HELP emcecs_cluster_alerts_warning Number of current warning alerts for the cluster
# TYPE emcecs_cluster_alerts_warning counter
# HELP emcecs_cluster_bad_disks Current count of bad disks in cluster
# TYPE emcecs_cluster_bad_disks gauge
# HELP emcecs_cluster_bad_nodes Current count of bad nodes in cluster
# TYPE emcecs_cluster_bad_nodes gauge
# HELP emcecs_cluster_chunks_pending_xor Number of chunks pending xor
# TYPE emcecs_cluster_chunks_pending_xor gauge
# HELP emcecs_cluster_data_replication_pending Data awaiting replication in bytes
# TYPE emcecs_cluster_data_replication_pending gauge
# HELP emcecs_cluster_good_disks Current count of good disks in cluster
# TYPE emcecs_cluster_good_disks gauge
# HELP emcecs_cluster_good_nodes Current count of good nodes in cluster
# TYPE emcecs_cluster_good_nodes gauge
# HELP emcecs_cluster_journal_replication_pending Journal data awaiting replication in bytes
# TYPE emcecs_cluster_journal_replication_pending gauge
# HELP emcecs_cluster_last_replication_timestamp Unix timestamp of last completed replication
# TYPE emcecs_cluster_last_replication_timestamp counter
# HELP emcecs_cluster_replication_egress_traffic Replication egress traffic in bytes/sec
# TYPE emcecs_cluster_replication_egress_traffic gauge
# HELP emcecs_cluster_replication_ingress_traffic Replication ingress traffic in bytes/sec
# TYPE emcecs_cluster_replication_ingress_traffic gauge
# HELP emcecs_cluster_space_free Cluster space free in Bytes
# TYPE emcecs_cluster_space_free gauge
# HELP emcecs_cluster_space_total Cluster size in Bytes
# TYPE emcecs_cluster_space_total gauge
# HELP emcecs_cluster_transaction_error Count of transaction errors
# TYPE emcecs_cluster_transaction_error counter
# HELP emcecs_cluster_transaction_error_detail error codes broken down by protocol category and error
# TYPE emcecs_cluster_transaction_error_detail counter
# HELP emcecs_cluster_transaction_read_bandwidth Cluster transaction read bandwidth in MB/S
# TYPE emcecs_cluster_transaction_read_bandwidth gauge
# HELP emcecs_cluster_transaction_read_latency Transaction read latency in ms
# TYPE emcecs_cluster_transaction_read_latency gauge
# HELP emcecs_cluster_transaction_read_per_second Cluster transactions read in transactions per second
# TYPE emcecs_cluster_transaction_read_per_second gauge
# HELP emcecs_cluster_transaction_success Count of transaction success
# TYPE emcecs_cluster_transaction_success counter
# HELP emcecs_cluster_transaction_write_bandwidth Cluster transaction write bandwidth in MB/S
# TYPE emcecs_cluster_transaction_write_bandwidth gauge
# HELP emcecs_cluster_transaction_write_latency Transaction write latency in ms
# TYPE emcecs_cluster_transaction_write_latency gauge
# HELP emcecs_cluster_transaction_write_per_second Cluster transactions write in transactions per second
# TYPE emcecs_cluster_transaction_write_per_second gauge
# HELP emcecs_node_activeConnections Number of current active connections on node
# TYPE emcecs_node_activeConnections gauge
# HELP emcecs_node_dtTotal Total number of DTs on node
# TYPE emcecs_node_dtTotal gauge
# HELP emcecs_node_dtUnknown Number of dt in unknown state on node
# TYPE emcecs_node_dtUnknown gauge
# HELP emcecs_node_dtUnready Number of dt in unready state on node
# TYPE emcecs_node_dtUnready gauge
````

### Dell EMC ECS Metering

````
# HELP emcecs_metering_namespace_object_count total count of objects in namespace
# TYPE emcecs_metering_namespace_object_count gauge
# HELP emcecs_metering_namespacequota quota information for namespace in KB
# TYPE emcecs_metering_namespacequota gauge
````

### ECS Exporter Application Stats

The following items are presented on the /metrics endpoint which gives the prometheus stats for the exporter application

```
# HELP emcecs_collection_success returns either 1 or 0 depending on success labeled by target_name
# TYPE emcecs_collection_success gauge
# HELP emcecs_collector_build_info A metric with a constant '1' value labeled by version, commitid and goversion exporter was built
# TYPE emcecs_collector_build_info gauge
# HELP emcecs_request_errors_total Total errors in requests to the ECS exporter
# TYPE emcecs_request_errors_total counter
# HELP emcecs_authtoken_cache_counter_hit count of authtoken cache hits
# TYPE emcecs_authtoken_cache_counter_hit counter
# HELP emcecs_authtoken_cache_counter_miss count of authtoken cache misses
# TYPE emcecs_authtoken_cache_counter_miss counter
```

## Building

This exporter can run on any go supported platform. As of version 1.2 we have moved to using Go 1.11 and higher. Testing is done with Go 1.12 but go 1.11 should work for anyone using it.

To build run:
`go build`

You can also run:
`go get github.com/paychex/prometheus-emcecs-exporter`

## Refrences

- https://www.emc.com/techpubs/api/ecs/v2-0-0-0/index.htm

## Author

This exporter was originally written by [Mark DeNeve](https://github.com/xphyr)