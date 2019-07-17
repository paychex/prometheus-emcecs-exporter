package ecsconfig

import (
	"flag"

	"github.com/jamiealquiza/envy"
)

type ecsConfig struct {
	UserName string
	Password string
	MgmtPort int
	ObjPort  int
}

type exporterConfig struct {
	BindAddress string
	BindPort    int
	Debug       bool
}

// Config is a container for settings modifiable by the user
type Config struct {
	ECS      ecsConfig
	Exporter exporterConfig
}

var (
	ecsMgmtPort   = flag.Int("mgmt_port", 4443, "The port which ecs listens to for administration")
	ecsObjPort    = flag.Int("obj_port", 9021, "The port which ecs listens to for object calls")
	ecsUserName   = flag.String("username", "defaultUser", "Username")
	ecsPassword   = flag.String("password", "defaultPass", "Password")
	listenAddress = flag.String("bind_address", "localhost", "Exporter bind address")
	listenPort    = flag.Int("bind_port", 9438, "Exporter bind port")
	debugLevel    = flag.Bool("debug", false, "enable  debug messages")
)

func init() {

	envy.Parse("ECSENV") // looks for ECSENV_USERNAME, ECSENV_PASSWORD, ECSENV_BINDPORT etc
	flag.Parse()

}

// GetConfig returns an instance of Config containing the resulting parameters
// to the program
func GetConfig() *Config {
	return &Config{
		ECS: ecsConfig{
			UserName: *ecsUserName,
			Password: *ecsPassword,
			MgmtPort: *ecsMgmtPort,
			ObjPort:  *ecsObjPort,
		},
		Exporter: exporterConfig{
			BindAddress: *listenAddress,
			BindPort:    *listenPort,
			Debug:       *debugLevel,
		},
	}
}
