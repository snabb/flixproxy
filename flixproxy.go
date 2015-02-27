//
// flixproxy.go
//
// Copyright © 2015 Janne Snabb <snabb AT epipe.com>
//
// This file is part of Flixproxy.
//
// Flixproxy is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Flixproxy is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Flixproxy. If not, see <http://www.gnu.org/licenses/>.
//

// Flixproxy - DNS, HTTP and TLS proxy
//
// Please see https://github.com/snabb/flixproxy for more information.
package main

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/ogier/pflag"
	"github.com/snabb/flixproxy/access"
	"github.com/snabb/flixproxy/dnsproxy"
	"github.com/snabb/flixproxy/httpproxy"
	"github.com/snabb/flixproxy/tlsproxy"
	"gopkg.in/inconshreveable/log15.v2"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

// Default configuration file location:
const CONFIG_FILE = "flixproxy.conf"

type config struct {
	Access  access.Config
	Logging []LoggingTarget
	DNS     dnsproxy.Config
	HTTP    httpproxy.Config
	TLS     tlsproxy.Config
}

func parseConfig(configFile string) (config, error) {
	var config config
	md, err := toml.DecodeFile(configFile, &config)
	if err != nil {
		return config, err
	}
	undecoded := md.Undecoded()
	if len(undecoded) > 0 {
		return config, fmt.Errorf("invalid configuration settings: %v", md.Undecoded())
	}
	return config, nil
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	configFile := pflag.StringP("conf", "c", CONFIG_FILE, "configuration file")
	testConfig := pflag.BoolP("test", "t", false, "test configuration")
	version := pflag.BoolP("version", "v", false, "version")

	pflag.Parse()

	if pflag.NArg() > 0 {
		pflag.Usage()
		os.Exit(2)
	}

	logger := log15.New()

	config, err := parseConfig(*configFile)
	if err != nil {
		logger.Crit("error parsing configuration", "err", err)
		os.Exit(2)
	}
	if *testConfig {
		fmt.Println("Configuration file parsed successfully.")
		os.Exit(0)
	}
	if *version {
		printVersion()
		os.Exit(0)
	}
	setupLogging(logger, config.Logging)

	logger.Info("starting listeners")

	var mydnsproxy *dnsproxy.DNSProxy
	if config.DNS.Listen != "" {
		mydnsproxy = dnsproxy.New(config.DNS, config.Access, logger.New("s", "DNS_"))
	}
	var myhttpproxy *httpproxy.HTTPProxy
	if config.HTTP.Listen != "" {
		myhttpproxy = httpproxy.New(config.HTTP, config.Access, logger.New("s", "HTTP"))
	}
	var mytlsproxy *tlsproxy.TLSProxy
	if config.TLS.Listen != "" {
		mytlsproxy = tlsproxy.New(config.TLS, config.Access, logger.New("s", "TLS_"))
	}

	sigCexit := make(chan os.Signal)
	signal.Notify(sigCexit, syscall.SIGTERM, syscall.SIGINT) // terminate gracefully

	logger.Info("entering main loop")
MAINLOOP:
	for {
		select {
		// there will probably be something more here in the future XXX
		case <-sigCexit:
			logger.Debug("signal SIGTERM received")
			break MAINLOOP
		}
	}
	logger.Info("exiting, stopping listeners")
	if mydnsproxy != nil {
		mydnsproxy.Stop()
	}
	if myhttpproxy != nil {
		myhttpproxy.Stop()
	}
	if mytlsproxy != nil {
		mytlsproxy.Stop()
	}
	logger.Info("bye")
}

func getGoEnvironment() string {
	return fmt.Sprintf("%s %s (%s/%s)", runtime.Compiler, runtime.Version(),
		runtime.GOOS, runtime.GOARCH)
}

func printVersion() {
	fmt.Println("Flixproxy", VERSION, "- DNS, HTTP and TLS proxy")
	fmt.Println("Built with", getGoEnvironment())
	fmt.Println(`
Copyright © 2015 Janne Snabb <snabb AT epipe.com>

Flixproxy is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Flixproxy is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with flixproxy. If not, see <http://www.gnu.org/licenses/>.
`)
}

// eof
