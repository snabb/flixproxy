//
// httproxy.go
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

package httpproxy

import (
	"bufio"
	"github.com/snabb/flixproxy/access"
	"github.com/snabb/flixproxy/util"
	"gopkg.in/inconshreveable/log15.v2"
	"net"
	"strings"
)

type HTTPProxy struct {
	config Config
	access access.Checker
	logger log15.Logger
}

type Config struct {
	Id         string
	Listen     string
	Upstreams  []string
	Deadline   int64
	Idle       int64
	LogRequest bool
}

func New(config Config, access access.Checker, logger log15.Logger) (httpProxy *HTTPProxy) {
	if config.Id != "" {
		logger = logger.New("id", config.Id)
	}
	httpProxy = &HTTPProxy{
		config: config,
		access: access,
		logger: logger,
	}
	go httpProxy.doProxy()

	return
}

func (httpProxy *HTTPProxy) Stop() {
	// something
}

func (httpProxy *HTTPProxy) doProxy() {
	httpProxy.logger.Info("starting tcp listener", "listen", httpProxy.config.Listen)
	listener, err := net.Listen("tcp", httpProxy.config.Listen)
	if err != nil {
		httpProxy.logger.Crit("listen tcp error", "listen", httpProxy.config.Listen, "err", err)
		return
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			httpProxy.logger.Error("accept error", "listen", httpProxy.config.Listen, "err", err)
			continue
		}
		if httpProxy.access.AllowedAddr(conn.RemoteAddr()) {
			go httpProxy.handleHTTPConnection(conn)
		} else {
			httpProxy.logger.Warn("access denied", "src", conn.RemoteAddr())

			go conn.Close()
		}
	}
}

func (httpProxy *HTTPProxy) handleHTTPConnection(downstream net.Conn) {
	util.SetDeadlineSeconds(downstream, httpProxy.config.Deadline)

	logger := httpProxy.logger.New("src", downstream.RemoteAddr())

	reader := bufio.NewReader(downstream)
	hostname := ""
	var lines []string
	var requestLine string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if netError, ok := err.(net.Error); ok && netError.Timeout() {
				logger.Info("timeout reading request")
			} else {
				logger.Error("error reading request", "err", err)
			}
			downstream.Close()
			return
		}
		lines = append(lines, line)
		line = strings.TrimSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\r")
		if len(lines) == 1 {
			// this is the HTTP Request-Line
			requestLine = line
			continue
		}
		if line == "" {
			// end of HTTP headers
			break
		}
		if strings.HasPrefix(line, "Host:") {
			hostname = strings.TrimPrefix(line, "Host:")
			hostname = strings.TrimSpace(hostname)
			break
		}
	}
	if hostname == "" {
		logger.Error("no hostname found", "request", requestLine)
		downstream.Close()
		return
	}
	if strings.Index(hostname, ":") == -1 {
		hostname = hostname + ":80" // XXX should use our local port number instead?
	}
	logger = logger.New("backend", hostname)

	if httpProxy.config.LogRequest {
		logger = logger.New("request", requestLine)
	}
	if util.ManyGlob(httpProxy.config.Upstreams, hostname) == false {
		logger.Error("backend not allowed")
		downstream.Close()
		return
	}
	upstream, err := net.Dial("tcp", hostname)
	if err != nil {
		logger.Error("error connecting to backend", "err", err)
		downstream.Close()
		return
	}
	logger.Debug("connected to backend")

	util.SetDeadlineSeconds(upstream, httpProxy.config.Deadline)

	for _, line := range lines {
		if _, err = upstream.Write([]byte(line)); err != nil {
			logger.Error("error writing to backend", "err", err)
			upstream.Close()
			downstream.Close()
			return
		}
	}

	// get all bytes buffered in bufio.Reader and send them to upstream so that we can resume
	// using original net.Conn
	buffered, err := util.ReadBufferedBytes(reader)
	if err != nil {
		logger.Error("error reading buffered bytes", "err", err)
		upstream.Close()
		downstream.Close()
		return
	}
	if _, err = upstream.Write(buffered); err != nil {
		logger.Error("error writing to backend", "err", err)
		upstream.Close()
		downstream.Close()
		return
	}
	// reset current deadlines
	util.SetDeadlineSeconds(upstream, 0)
	util.SetDeadlineSeconds(downstream, 0)

	go util.CopyAndCloseWithIdleTimeout(upstream, downstream, httpProxy.config.Idle)
	go util.CopyAndCloseWithIdleTimeout(downstream, upstream, httpProxy.config.Idle)
}

// eof
