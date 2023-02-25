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
	"io/ioutil"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/ogier/pflag"
	"github.com/snabb/flixproxy/access"
	"github.com/snabb/flixproxy/dnsproxy"
	"github.com/snabb/flixproxy/httpproxy"
	"github.com/snabb/flixproxy/tlsproxy"
	"gopkg.in/inconshreveable/log15.v2"
	"gopkg.in/yaml.v2"
)

// Default configuration file location:
const CONFIG_FILE = "flixproxy.conf"

type config struct {
	Acl     access.Config
	Logging []LoggingTarget
	DNS     []dnsproxy.Config
	HTTP    []httpproxy.Config
	TLS     []tlsproxy.Config
}

func parseConfig(configFile string) (config config, err error) {
	configText, err := ioutil.ReadFile(configFile)
	if err != nil {
		return config, err
	}
	err = yaml.Unmarshal(configText, &config)
	return config, err
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
	if *version {
		printVersion()
		os.Exit(0)
	}

	logger := log15.New()

	config, err := parseConfig(*configFile)
	if err != nil {
		logger.Crit("error parsing configuration", "err", err)
		os.Exit(2)
	}
	if *testConfig {
		fmt.Println("Configuration file parsed successfully.")
		fmt.Printf("%+v\n", config)
		os.Exit(0)
	}
	setupLogging(logger, config.Logging)

	logger.Info("starting listeners")

	var proxies []interface {
		Stop()
	}
	for _, proxyConfig := range config.DNS {
		proxies = append(proxies,
			dnsproxy.New(proxyConfig, config.Acl.GetAcl(proxyConfig.Acl), logger.New("s", "DNS")))
	}
	for _, proxyConfig := range config.HTTP {
		proxies = append(proxies,
			httpproxy.New(proxyConfig, config.Acl.GetAcl(proxyConfig.Acl), logger.New("s", "HTTP")))
	}
	for _, proxyConfig := range config.TLS {
		proxies = append(proxies,
			tlsproxy.New(proxyConfig, config.Acl.GetAcl(proxyConfig.Acl), logger.New("s", "TLS")))
	}

	sigCexit := make(chan os.Signal, 1)
	signal.Notify(sigCexit, syscall.SIGTERM, syscall.SIGINT) // terminate gracefully

	sigChup := make(chan os.Signal, 1)
	signal.Notify(sigChup, syscall.SIGHUP) // reopen logs

	logger.Info("entering main loop")
MAINLOOP:
	for {
		select {
		// there will probably be something more here in the future XXX
		case <-sigCexit:
			logger.Debug("exit signal received")
			break MAINLOOP
		case <-sigChup:
			setupLogging(logger, config.Logging)
			logger.Debug("reopened logs")
		}
	}
	logger.Info("exiting, stopping listeners")
	for _, proxy := range proxies {
		proxy.Stop()
	}
	logger.Info("bye")
}

func getGoEnvironment() (environment string) {
	return fmt.Sprintf("%s %s (%s/%s)", runtime.Compiler, runtime.Version(),
		runtime.GOOS, runtime.GOARCH)
}

func printVersion() {
	fmt.Println("Flixproxy", VERSION, "- DNS, HTTP and TLS proxy")
	fmt.Println("Built with", getGoEnvironment())
	fmt.Print(`
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
along with Flixproxy. If not, see <http://www.gnu.org/licenses/>.

`)
}

// eof
