package ecsclient

import (
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/common/log"
	"github.com/tidwall/gjson"
)

// EcsClient is used to persist connection to an ECS Cluster
type EcsClient struct {
	UserName       string
	Password       string
	AuthToken      string
	ClusterAddress string
	nodeList       []string
	EcsVersion     string
	ErrorCount     float64
}

type NodeState struct {
	TotalDTnum        float64 `xml:"entry>total_dt_num"`
	UnreadyDTnum      float64 `xml:"entry>unready_dt_num"`
	UnknownDTnum      float64 `xml:"entry>unknown_dt_num"`
	NodeIP            string
	ActiveConnections float64 `xml:"entry>load_factor"`
}

type dataNodes struct {
	DataNodes   []string
	VersionInfo string
}

type pingList struct {
	Xmlns  string   `xml:"xmlns,attr"`
	Name   []string `xml:"PingItem>Name"`
	Value  float64  `xml:"PingItem>Value"`
	Status []string `xml:"PingItem>Status"`
	Text   []string `xml:"PingItem>Text"`
}

// RetrieveAuthToken and store as part of the client struct for future use
func (c *EcsClient) RetrieveAuthToken() (authToken string, err error) {
	reqLoginURL := "https://" + c.ClusterAddress + ":4443/login"

	log.Debugf("Using the following info to log into the ECS, username: %v, URL: %v", c.UserName, c.ClusterAddress)

	// using
	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	},
		Timeout: 15 * time.Second}
	req, _ := http.NewRequest("GET", reqLoginURL, nil)
	req.SetBasicAuth(c.UserName, c.Password)
	resp, err := client.Do(req)
	if err != nil {
		log.Infof("\n - Error connecting to ECS: %s", err)
		return "", err
	}
	defer resp.Body.Close()

	log.Debugf("Response Status Code: %v", resp.StatusCode)
	log.Debugf("Response Status: %v", resp.Status)
	log.Debugf("Response Body: %v", resp.Body)
	log.Debugf("AuthToken is: %v", resp.Header.Get("X-Sds-Auth-Token"))

	if resp.StatusCode != 200 {
		// we didnt get a good response code, so bailing out
		log.Infoln("Got a non 200 response code: ", resp.StatusCode)
		log.Debugln("response was: ", resp)
		c.ErrorCount++
		return "", fmt.Errorf("received non 200 error code: %v. the response was: %v", resp.Status, resp)
	}
	c.AuthToken = resp.Header.Get("X-Sds-Auth-Token")
	return resp.Header.Get("X-Sds-Auth-Token"), nil

}

// Logout closes out the connection to ECS when we are done.
// if we dont log out we use up all of the available login tokens
func (c *EcsClient) Logout() error {
	// there’s a maximum number of login tokens (100) per user
	// need to log out to throw away the token since we arent set up for caching...

	reqLogoutURL := "https://" + c.ClusterAddress + ":4443/logout"

	log.Infof("Logging out of %s", c.ClusterAddress)

	// we dont need the reply data, so just throw it away
	_, err := c.CallECSAPI(reqLogoutURL)
	if err != nil {
		log.Infof("Error logging out of ECS: %s", c.ClusterAddress)
		return err
	}
	c.AuthToken = ""
	return nil
}

func (c *EcsClient) CallECSAPI(request string) (response string, err error) {
	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	},
		Timeout: 45 * time.Second}
	req, _ := http.NewRequest("GET", request, nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-SDS-AUTH-TOKEN", c.AuthToken)
	resp, err := client.Do(req)
	if err != nil {
		log.Infof("\n - Error connecting to ECS: %s", err)
		return "", fmt.Errorf("error connecting to : %v. the error was: %v", request, err)
	}
	defer resp.Body.Close()
	respText, err := ioutil.ReadAll(resp.Body)
	s := string(respText)

	if resp.StatusCode != 200 {
		log.Infof("Got error code: %v when accessing URL: %s\n Body text is: %s\n", resp.StatusCode, request, respText)
		return "", fmt.Errorf("error connecting to : %v. the error was: %v", request, resp.StatusCode)
	}
	return s, nil
}

// RetrieveReplState will return a struct containing the state of the ECS cluster on query
func (c *EcsClient) RetrieveReplState() (EcsReplState, error) {
	// this will only pull the current stats, which is what we want for this application
	// reqStatusURL := "https://" + c.ClusterAddress + ":4443/dashboard/zones/localzone?dataType=current"
	reqStatusURL := "https://" + c.ClusterAddress + ":4443/dashboard/zones/localzone/replicationgroups"

	s, err := c.CallECSAPI(reqStatusURL)
	if err != nil {
		return EcsReplState{}, err
	}

	return EcsReplState{
		RgName:                                   gjson.Get(s, "name").String(),
		ReplicationIngressTraffic:                gjson.Get(s, "replicationIngressTraffic").Float(),
		ReplicationEgressTraffic:                 gjson.Get(s, "replicationEgressTraffic").Float(),
		ChunksRepoPendingReplicationTotalSize:    gjson.Get(s, "chunksRepoPendingReplicationTotalSize").Float(),
		ChunksJournalPendingReplicationTotalSize: gjson.Get(s, "chunksJournalPendingReplicationTotalSize").Float(),
		ChunksPendingXorTotalSize:                gjson.Get(s, "chunksPendingXorTotalSize").Float(),
		ReplicationRpoTimestamp:                  gjson.Get(s, "replicationRpoTimestamp").Float(),
	}, nil
}

// RetrieveClusterState will return a struct containing the state of the ECS cluster on query
func (c *EcsClient) RetrieveClusterState() (EcsClusterState, error) {

	// this will only pull the current stats, which is what we want for this application
	// reqStatusURL := "https://" + c.ClusterAddress + ":4443/dashboard/zones/localzone?dataType=current"
	reqStatusURL := "https://" + c.ClusterAddress + ":4443/dashboard/zones/localzone"

	s, err := c.CallECSAPI(reqStatusURL)
	if err != nil {
		return EcsClusterState{}, err
	}

	fields := EcsClusterState{
		VdcName:                               gjson.Get(s, "name").String(),
		NumBadDisks:                           gjson.Get(s, "numBadDisks").Float(),
		NumBadNodes:                           gjson.Get(s, "numBadNodes").Float(),
		NumGoodNodes:                          gjson.Get(s, "numGoodNodes").Float(),
		NumGoodDisks:                          gjson.Get(s, "numGoodDisks").Float(),
		AlertsNumUnackCritical:                gjson.Get(s, "alertsNumUnackCritical.0.Count").Float(),
		AlertsNumUnackError:                   gjson.Get(s, "alertsNumUnackError.0.Count").Float(),
		AlertsNumUnackInfo:                    gjson.Get(s, "alertsNumUnackInfo.0.Count").Float(),
		AlertsNumUnackWarning:                 gjson.Get(s, "alertsNumUnackWarning.0.Count").Float(),
		DiskSpaceFree:                         gjson.Get(s, "diskSpaceFreeCurrent.0.Space").Float(),
		DiskSpaceTotal:                        gjson.Get(s, "diskSpaceTotalCurrent.0.Space").Float(),
		DiskSpaceAllocated:                    gjson.Get(s, "diskSpaceAllocatedCurrent.0.Space").Float(),
		TransactionErrorsTotal:                gjson.Get(s, "transactionErrorsCurrent.errorSuccessTotals.0.errorTotal").Float(),
		TransactionSuccessTotal:               gjson.Get(s, "transactionErrorsCurrent.errorSuccessTotals.0.successTotal").Float(),
		TransactionReadLatency:                gjson.Get(s, "transactionReadLatencyCurrent.0.Latency").Float(),  //validated
		TransactionWriteLatency:               gjson.Get(s, "transactionWriteLatencyCurrent.0.Latency").Float(), //validated
		TransactionReadTransactionsPerSecond:  gjson.Get(s, "transactionReadTransactionsPerSecCurrent.0.TPS").Float(),
		TransactionWriteTransactionsPerSecond: gjson.Get(s, "transactionWriteTransactionsPerSecCurrent.0.TPS").Float(),
		TransactionWriteBandwidthCurrent:      gjson.Get(s, "transactionWriteBandwidthCurrent.0.Bandwidth").Float(),
		TransactionReadBandwidthCurrent:       gjson.Get(s, "transactionReadBandwidthCurrent.0.Bandwidth").Float(),
	}
	return fields, nil

}

// RetrieveNodeCount returns number of nodes found in the cluster
// since the "nodeList" is private
func (c *EcsClient) RetrieveNodeCount() int {
	return len(c.nodeList)
}

// RetrieveNodeInfo will retrieve a list of individual nodes in the cluster
// this is used to pull DTstats later on
func (c *EcsClient) RetrieveNodeInfo() {
	parsedOutput := &dataNodes{}
	// ECS gives you a way to get the node IPs, BUT it wont do it without a namespace
	// Interestingly you can give it ANY namespace, including ones that dont exist
	reqStatusURL := "http://" + c.ClusterAddress + ":9020/?endpoint"
	log.Debug("node ip url is: " + reqStatusURL)

	client := &http.Client{}
	req, _ := http.NewRequest("GET", reqStatusURL, nil)
	req.Header.Set("x-emc-namespace", "nodeips")
	resp, err := client.Do(req)

	if err != nil {
		log.Info("Error connecting to ECS Cluster at: " + reqStatusURL)
		c.nodeList = nil
		c.EcsVersion = ""
		c.ErrorCount++
		return
	}
	defer resp.Body.Close()

	bytes, _ := ioutil.ReadAll(resp.Body)

	log.Debugf("Output from node poll is %s", bytes)
	xml.Unmarshal(bytes, parsedOutput)
	c.nodeList = parsedOutput.DataNodes
	c.EcsVersion = parsedOutput.VersionInfo

}

func (c *EcsClient) retrieveNodeState(node string, ch chan<- NodeState) {
	parsedOutput := &NodeState{}
	parsedPing := &pingList{}
	parsedOutput.NodeIP = node

	log.Debug("this is the node I am querying ", node)
	reqStatusURL := "http://" + node + ":9101/stats/dt/DTInitStat"
	log.Debug("URL we are checking is ", reqStatusURL)

	resp, err := http.Get(reqStatusURL)
	if err != nil {
		log.Info("Error connecting to ECS Cluster at: " + reqStatusURL)
		c.ErrorCount++
		ch <- *parsedOutput
		return
	}
	defer resp.Body.Close()

	bytes, _ := ioutil.ReadAll(resp.Body)
	xml.Unmarshal(bytes, parsedOutput)

	// ECS supplies the current number of active connections, but its per node
	// and its part of the s3 retrieval api (ie port 9020) so lets get this and pass it along as well
	// and its in yet another format ... or at least xml layed out differently, so more processing is needed
	reqConnectionsURL := "http://" + node + ":9020/?ping"
	log.Debug("URL we are checking for connections is ", reqConnectionsURL)

	respConn, err := http.Get(reqConnectionsURL)
	if err != nil {
		log.Info("Error connecting to ECS Cluster at: " + reqStatusURL)
		c.ErrorCount++
		ch <- *parsedOutput
		return
	}
	defer respConn.Body.Close()

	bytesConnection, _ := ioutil.ReadAll(respConn.Body)
	xml.Unmarshal(bytesConnection, parsedPing)
	parsedOutput.ActiveConnections = parsedPing.Value

	ch <- *parsedOutput
}

// RetrieveNodeStateParallel pulls all the dtstate from nodes in the cluster all at once
func (c *EcsClient) RetrieveNodeStateParallel() []NodeState {
	var NodeStates []NodeState

	ch := make(chan NodeState)

	for _, node := range c.nodeList {
		go c.retrieveNodeState(node, ch)
	}

	for range c.nodeList {
		NodeStates = append(NodeStates, <-ch)
	}
	return NodeStates
}
