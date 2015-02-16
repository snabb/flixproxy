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
	Access access.Config
	DNS    dnsproxy.Config
	HTTP   httpproxy.Config
	TLS    tlsproxy.Config
}

func parseConfig(configFile string) (config config, err error) {
	_, err = toml.DecodeFile(configFile, &config)
	return
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	var configFile string

	pflag.StringVarP(&configFile, "conf", "c", CONFIG_FILE, "configuration file")
	pflag.Parse()

	if pflag.NArg() > 0 {
		pflag.Usage()
		os.Exit(2)
	}

	logger := log15.New()

	config, err := parseConfig(configFile)
	if err != nil {
		logger.Crit("error parsing configuration", "err", err)
		os.Exit(2)
	}

	logger.Info("starting listeners")

	var mydnsproxy *dnsproxy.DNSProxy
	if config.DNS.Listen != "" {
		mydnsproxy = dnsproxy.New(config.DNS, config.Access, logger.New("svc", "DNS"))
	}
	var myhttpproxy *httpproxy.HTTPProxy
	if config.HTTP.Listen != "" {
		myhttpproxy = httpproxy.New(config.HTTP, config.Access, logger.New("svc", "HTTP"))
	}
	var mytlsproxy *tlsproxy.TLSProxy
	if config.TLS.Listen != "" {
		mytlsproxy = tlsproxy.New(config.TLS, config.Access, logger.New("svc", "TLS"))
	}

	sigCexit := make(chan os.Signal)
	signal.Notify(sigCexit, syscall.SIGTERM, syscall.SIGINT) // terminate gracefully

	logger.Info("entering main loop")
MAINLOOP:
	for {
		select {
		// there will probably be something more here in the future XXX
		case <-sigCexit:
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

// eof
