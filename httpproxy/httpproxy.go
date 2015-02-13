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
	"container/list"
	"github.com/snabb/flixproxy/access"
	"github.com/snabb/flixproxy/util"
	"log"
	"net"
	"strings"
)

type HTTPProxy struct {
	config Config
	access *access.Access
	logger *log.Logger
}

type Config struct {
	Listen    string
	Upstreams []string
}

func New(config Config, access *access.Access, logger *log.Logger) (httpProxy *HTTPProxy) {
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
	listener, err := net.Listen("tcp", httpProxy.config.Listen)
	if err != nil {
		httpProxy.logger.Fatalln("HTTP listen tcp "+
			httpProxy.config.Listen+" error:", err)
		return
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			httpProxy.logger.Println("HTTP accept "+
				httpProxy.config.Listen+" error:", err)
		}
		if httpProxy.access.AllowedNetAddr(conn.RemoteAddr()) {
			go httpProxy.handleHTTPConnection(conn)
		} else {
			go conn.Close()
		}
	}
}

func (httpProxy *HTTPProxy) handleHTTPConnection(downstream net.Conn) {
	reader := bufio.NewReader(downstream)
	hostname := ""
	readLines := list.New()
	for hostname == "" {
		line, err := reader.ReadString('\n')
		if err != nil {
			httpProxy.logger.Printf("HTTP request from %s: %s\n",
				downstream.RemoteAddr(), err)
			downstream.Close()
			return
		}
		line = strings.TrimSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\r")
		readLines.PushBack(line)
		if line == "" {
			// end of HTTP headers
			break
		}
		if strings.HasPrefix(line, "Host: ") {
			hostname = strings.TrimPrefix(line, "Host: ")
			break
		}
	}
	if hostname == "" {
		httpProxy.logger.Printf("HTTP request from %s: no hostname found\n",
			downstream.RemoteAddr())
		downstream.Close()
		return
	}
	if strings.Index(hostname, ":") == -1 {
		hostname = hostname + ":80"
	}
	if util.ManyGlob(httpProxy.config.Upstreams, hostname) == false {
		httpProxy.logger.Printf("HTTP request from %s: backend \"%s\" not allowed\n",
			downstream.RemoteAddr(), hostname)
		downstream.Close()
		return
	}
	upstream, err := net.Dial("tcp", hostname)
	if err != nil {
		httpProxy.logger.Printf("HTTP request from %s: error connecting to backend \"%s\": %s\n",
			downstream.RemoteAddr(), hostname, err)
		downstream.Close()
		return
	}
	httpProxy.logger.Printf("HTTP request from %s connected to backend \"%s\"\n",
		downstream.RemoteAddr(), hostname)

	for element := readLines.Front(); element != nil; element = element.Next() {
		line := element.Value.(string)
		upstream.Write([]byte(line))
		upstream.Write([]byte("\r\n"))
	}

	go util.CopyAndClose(upstream, reader)
	go util.CopyAndClose(downstream, upstream)
}

// eof
