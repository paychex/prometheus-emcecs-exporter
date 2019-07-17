package ecsclient

import (
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	ecsconfig "github.com/paychex/prometheus-emcecs-exporter/pkg/config"
	log "github.com/sirupsen/logrus"

	"github.com/tidwall/gjson"
)

// EcsClient is used to persist connection to an ECS Cluster
type EcsClient struct {
	authToken      string
	ClusterAddress string
	nodeListMgmtIP []string
	nodeListDataIP []string
	EcsVersion     string
	ErrorCount     float64
	Config         *ecsconfig.Config
	httpClient     *http.Client
}

type NodeState struct {
	TotalDTnum        float64 `xml:"entry>total_dt_num"`
	UnreadyDTnum      float64 `xml:"entry>unready_dt_num"`
	UnknownDTnum      float64 `xml:"entry>unknown_dt_num"`
	NodeIP            string
	ActiveConnections float64 `xml:"entry>load_factor"`
}

type pingList struct {
	Xmlns  string   `xml:"xmlns,attr"`
	Name   []string `xml:"PingItem>Name"`
	Value  float64  `xml:"PingItem>Value"`
	Status []string `xml:"PingItem>Status"`
	Text   []string `xml:"PingItem>Text"`
}

func NewECSClient(clusterAddress string, ecsconfig *ecsconfig.Config) *EcsClient {
	return &EcsClient{
		ClusterAddress: clusterAddress,
		httpClient: &http.Client{Transport: &http.Transport{
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
			Timeout: 60 * time.Second},
		Config: ecsconfig,
	}
}

// RetrieveAuthToken and store as part of the client struct for future use
func (c *EcsClient) RetrieveAuthToken() (authToken string, err error) {
	reqLoginURL := "https://" + c.ClusterAddress + ":" + strconv.Itoa(c.Config.ECS.MgmtPort) + "/login"

	log.Debugf("Using the following info to log into the ECS, username: %v, URL: %v", c.Config.ECS.UserName, c.ClusterAddress)

	req, _ := http.NewRequest("GET", reqLoginURL, nil)
	req.SetBasicAuth(c.Config.ECS.UserName, c.Config.ECS.Password)
	resp, err := c.httpClient.Do(req)
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
	c.authToken = resp.Header.Get("X-Sds-Auth-Token")
	return resp.Header.Get("X-Sds-Auth-Token"), nil

}

// Login logs into the ecs cluster and retrieves and stores an auth token
func (c *EcsClient) Login() error {
	log.Info("Connecting to ECS Cluster: " + c.ClusterAddress)
	var err error

	for i := 1; i < 4; i++ {
		log.Debugf("Looking to see if we have a Auth Token for %s", c.ClusterAddress)
		if c.authToken == "" {
			log.Debug("Authtoken not found.")
			log.Debugf("Retrieving ECS authToken for %s", c.ClusterAddress)
			// get our authtoken for future interactions
			c.authToken, err = c.RetrieveAuthToken()
			if err != nil {
				log.Debugf("Error getting auth token for %s", c.ClusterAddress)
				return err
			}
		}

		log.Debugf("Authtoken pulled from cache for %s", c.ClusterAddress)

		// test to make sure that our auth token is good
		// if not delete it and loop back to our login logic above
		validateLoginURL := "https://" + c.ClusterAddress + ":" + strconv.Itoa(c.Config.ECS.MgmtPort) + "/user/whoami"
		_, err = c.CallECSAPI(validateLoginURL)
		if err == nil {
			break
		}
		// authToken we have cached is no good. blank it out and try again
		log.Info("AuthToken has expired. Invalidating and logging back in.")
		c.authToken = ""
	}
	if c.authToken == "" {
		// we looped and failed multiple times, so no need to go further
		log.Debugf("Error getting auth token for %s", c.ClusterAddress)
		return fmt.Errorf("error retrieving auth token")
	}
	return nil
}

// Logout closes out the connection to ECS when we are done.
// if we dont log out we use up all of the available login tokens
func (c *EcsClient) Logout() error {
	// there’s a maximum number of login tokens (100) per user
	// need to log out to throw away the token since we arent set up for caching...

	request := "https://" + c.ClusterAddress + ":" + strconv.Itoa(c.Config.ECS.MgmtPort) + "/logout"

	log.Infof("Logging out of %s", c.ClusterAddress)

	req, _ := http.NewRequest("GET", request, nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-SDS-AUTH-TOKEN", c.authToken)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Infof("\n - Error connecting to ECS: %s", err)
		return fmt.Errorf("error connecting to : %v. the error was: %v", request, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 401:
		// this just means we are already logged out.
		log.Infof("Already logged out of %s.", c.ClusterAddress)
	case 200:
		// we have succesfully logged out.
		log.Infof("Logged out of %s.", c.ClusterAddress)
	default:
		log.Infof("Got error code: %v while logging out of %s", resp.StatusCode, c.ClusterAddress)
		c.authToken = ""
		return fmt.Errorf("error connecting to : %v. the error was: %v", request, resp.StatusCode)
	}
	c.authToken = ""
	return nil
}

// CallECSAPI takes a string and calls the API leveraging the token we already have
func (c *EcsClient) CallECSAPI(request string) (response string, err error) {

	req, _ := http.NewRequest("GET", request, nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-SDS-AUTH-TOKEN", c.authToken)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Infof("\n - Error connecting to ECS: %s", err)
		return "", fmt.Errorf("error connecting to : %v. the error was: %v", request, err)
	}
	defer resp.Body.Close()
	respText, err := ioutil.ReadAll(resp.Body)
	s := string(respText)

	switch resp.StatusCode {
	case 401:
		// this just means we need to re-login so we will log in and then re-make the call
		// invalidate the authToken
		log.Debug("Got a 401 from ECS. Invalidating apiToken")
		c.authToken = ""
		err = c.Login()
		if err != nil {
			log.Infof("Got error code: %v when accessing URL: %s\n Body text is: %s\n", resp.StatusCode, request, respText)
			return "", fmt.Errorf("error connecting to : %v. the error was: %v", request, resp.StatusCode)
		}
		log.Debug("Should be all logged back in. Recursively re-calling API")
		return c.CallECSAPI(request)
	case 200:
		return s, nil
	default:
		log.Infof("Got error code: %v when accessing URL: %s\n Body text is: %s\n", resp.StatusCode, request, respText)
		return "", fmt.Errorf("error connecting to : %v. the error was: %v", request, resp.StatusCode)
	}

}

// RetrieveReplState will return a struct containing the state of the ECS cluster on query
func (c *EcsClient) RetrieveReplState() (EcsReplState, error) {
	// this will only pull the current stats, which is what we want for this application
	reqStatusURL := "https://" + c.ClusterAddress + ":" + strconv.Itoa(c.Config.ECS.MgmtPort) + "/dashboard/zones/localzone/replicationgroups?dataType=current"

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
	// reqStatusURL := "https://" + c.ClusterAddress + ":" + strconv.Itoa(c.Config.ECS.MgmtPort) + "/dashboard/zones/localzone?dataType=current"
	reqStatusURL := "https://" + c.ClusterAddress + ":" + strconv.Itoa(c.Config.ECS.MgmtPort) + "/dashboard/zones/localzone"

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
		TransactionErrorsTotal:                gjson.Get(s, "transactionErrors.errorSuccessTotals.0.errorTotal").Float(),
		TransactionSuccessTotal:               gjson.Get(s, "transactionErrors.errorSuccessTotals.0.successTotal").Float(),
		TransactionReadLatency:                gjson.Get(s, "transactionReadLatencyCurrent.0.Latency").Float(),  //validated
		TransactionWriteLatency:               gjson.Get(s, "transactionWriteLatencyCurrent.0.Latency").Float(), //validated
		TransactionReadTransactionsPerSecond:  gjson.Get(s, "transactionReadTransactionsPerSecCurrent.0.TPS").Float(),
		TransactionWriteTransactionsPerSecond: gjson.Get(s, "transactionWriteTransactionsPerSecCurrent.0.TPS").Float(),
		TransactionWriteBandwidthCurrent:      gjson.Get(s, "transactionWriteBandwidthCurrent.0.Bandwidth").Float(),
		TransactionReadBandwidthCurrent:       gjson.Get(s, "transactionReadBandwidthCurrent.0.Bandwidth").Float(),
	}

	// need to get the array of types and loop over it
	result := gjson.Get(s, "transactionErrors.types")
	result.ForEach(func(key, value gjson.Result) bool {

		// error type comes in as a string like so "403 (S3)"
		// it would be better if this was two fields, so we can break out counts for Protocol
		// or for error codes.  So we need to do some string manipulation
		errorType := strings.Fields(gjson.Get(value.String(), "errorType").String())
		s := errorType[1]

		transactionerror := EcsTransactionError{
			ErrorCode:  errorType[0],
			ErrorProto: s[1 : len(s)-1],
			Category:   gjson.Get(value.String(), "category").String(),
			ErrorCount: gjson.Get(value.String(), "errorCount").Float(),
		}
		fields.TransactionErrors = append(fields.TransactionErrors, transactionerror)
		return true
	})

	return fields, nil

}

// RetrieveNodeCount returns number of nodes found in the cluster
// since the "nodeList" is private
func (c *EcsClient) RetrieveNodeCount() int {
	return len(c.nodeListMgmtIP)
}

// RetrieveNodeInfoV2 will replace RetrieveNodeInfo code, getting nodes from the object API
// We should be able to make this a drop in replacement with just a little work.
func (c *EcsClient) RetrieveNodeInfoV2() {

	// Get the list of nodes from the Management API
	// we should do this each time to ensure that we have an up to date list of the nodes
	reqStatusURL := "https://" + c.ClusterAddress + ":" + strconv.Itoa(c.Config.ECS.MgmtPort) + "/vdc/nodes"

	s, err := c.CallECSAPI(reqStatusURL)
	if err != nil {
		return
	}

	// We need to zero out the current nodeListDataIP and nodeListMgmtIP
	// since we use append to build it back up ... if we dont this list just keeps growing
	c.nodeListDataIP = nil
	c.nodeListMgmtIP = nil

	resultData := gjson.Get(s, "node.#.data_ip")
	for _, ip := range resultData.Array() {
		// for
		c.nodeListDataIP = append(c.nodeListDataIP, ip.String())
	}
	resultMgmt := gjson.Get(s, "node.#.mgmt_ip")
	for _, ip := range resultMgmt.Array() {
		// for
		c.nodeListMgmtIP = append(c.nodeListMgmtIP, ip.String())
	}

	c.EcsVersion = gjson.Get(s, "node.0.version").String()

}

func (c *EcsClient) retrieveNodeState(node string, ch chan<- NodeState) {
	parsedOutput := &NodeState{}
	parsedPing := &pingList{}
	parsedOutput.NodeIP = node

	log.Debug("this is the node I am querying ", node)
	reqStatusURL := "http://" + node + ":9101/stats/dt/DTInitStat"
	log.Debug("URL we are checking is ", reqStatusURL)

	resp, err := c.httpClient.Get(reqStatusURL)
	if err != nil {
		log.Info("Error connecting to ECS Cluster at: " + reqStatusURL)
		c.ErrorCount++
		ch <- *parsedOutput
		return
	}
	defer resp.Body.Close()

	bytes, _ := ioutil.ReadAll(resp.Body)
	err = xml.Unmarshal(bytes, parsedOutput)
	if err != nil {
		log.Info("Error un-marshaling XML from: " + reqStatusURL)
		log.Info(err)
		c.ErrorCount++
		ch <- *parsedOutput
		return
	}

	// ECS supplies the current number of active connections, but its per node
	// and its part of the s3 retrieval api (ie port 9021) so lets get this and pass it along as well
	// and its in yet another format ... or at least xml layed out differently, so more processing is needed
	reqConnectionsURL := "https://" + node + ":" + strconv.Itoa(c.Config.ECS.ObjPort) + "/?ping"
	log.Debug("URL we are checking for connections is ", reqConnectionsURL)

	respConn, err := c.httpClient.Get(reqConnectionsURL)
	if err != nil {
		log.Info("Error connecting to ECS Cluster at: " + reqConnectionsURL)
		log.Info(err)
		c.ErrorCount++
		ch <- *parsedOutput
		return
	}
	defer respConn.Body.Close()

	bytesConnection, _ := ioutil.ReadAll(respConn.Body)
	err = xml.Unmarshal(bytesConnection, parsedPing)
	if err != nil {
		log.Info("Error un-marshaling XML from: " + reqConnectionsURL)
		log.Info(err)
		c.ErrorCount++
		ch <- *parsedOutput
		return
	}
	parsedOutput.ActiveConnections = parsedPing.Value

	ch <- *parsedOutput
}

// RetrieveNodeStateParallel pulls all the dtstate from nodes in the cluster all at once
func (c *EcsClient) RetrieveNodeStateParallel() []NodeState {
	var NodeStates []NodeState

	ch := make(chan NodeState)

	for _, node := range c.nodeListMgmtIP {
		go c.retrieveNodeState(node, ch)
	}

	for range c.nodeListMgmtIP {
		NodeStates = append(NodeStates, <-ch)
	}
	return NodeStates
}
