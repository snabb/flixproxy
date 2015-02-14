//
// tlsproxy.go
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

package tlsproxy

import (
	"github.com/snabb/flixproxy/access"
	"github.com/snabb/flixproxy/util"
	"io"
	"log"
	"net"
)

type TLSProxy struct {
	config Config
	access access.Checker
	logger *log.Logger
}

type Config struct {
	Listen    string
	Upstreams []string
	Deadline  int64
	Idle      int64
}

func New(config Config, access access.Checker, logger *log.Logger) (tlsProxy *TLSProxy) {
	tlsProxy = &TLSProxy{
		config: config,
		access: access,
		logger: logger,
	}
	go tlsProxy.doProxy()

	return
}

func (tlsProxy *TLSProxy) Stop() {
	// something
}

func (tlsProxy *TLSProxy) doProxy() {
	listener, err := net.Listen("tcp", tlsProxy.config.Listen)
	if err != nil {
		tlsProxy.logger.Fatalln("TLS listen tcp "+
			tlsProxy.config.Listen+" error:", err)
		return
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			tlsProxy.logger.Println("TLS accept "+
				tlsProxy.config.Listen+" error:", err)
		}
		if tlsProxy.access.AllowedAddr(conn.RemoteAddr()) {
			go tlsProxy.handleTLSConnection(conn)
		} else {
			go conn.Close()
		}
	}
}

func (tlsProxy *TLSProxy) handleTLSConnection(downstream net.Conn) {
	util.SetDeadlineSeconds(downstream, tlsProxy.config.Deadline)

	firstByte := make([]byte, 1)
	_, err := io.ReadFull(downstream, firstByte)
	if err != nil {
		tlsProxy.logger.Printf("TLS request from %s: error reading first byte: %s\n",
			downstream.RemoteAddr(), err)
		downstream.Close()
		return
	}
	if firstByte[0] != 0x16 { // recordTypeHandshake
		tlsProxy.logger.Printf("TLS request from %s: not TLS\n", downstream.RemoteAddr())
		downstream.Close()
		return
	}

	versionBytes := make([]byte, 2)
	_, err = io.ReadFull(downstream, versionBytes)
	if err != nil {
		tlsProxy.logger.Printf("TLS request from %s: error reading version bytes: %s\n",
			downstream.RemoteAddr(), err)
		downstream.Close()
		return
	}
	if versionBytes[0] < 3 || (versionBytes[0] == 3 && versionBytes[1] < 1) {
		tlsProxy.logger.Printf("TLS request from %s: error: SSL < 3.1 not supported\n",
			downstream.RemoteAddr())
		downstream.Close()
		return
	}

	restLengthBytes := make([]byte, 2)
	_, err = io.ReadFull(downstream, restLengthBytes)
	if err != nil {
		tlsProxy.logger.Printf("TLS request from %s: error reading restLength bytes: %s\n",
			downstream.RemoteAddr(), err)
		downstream.Close()
		return
	}
	restLength := (int(restLengthBytes[0]) << 8) + int(restLengthBytes[1])

	rest := make([]byte, restLength)
	_, err = io.ReadFull(downstream, rest)
	if err != nil {
		tlsProxy.logger.Printf("TLS request from %s: error reading rest of bytes: %s\n",
			downstream.RemoteAddr(), err)
		downstream.Close()
		return
	}
	if len(rest) == 0 || rest[0] != 1 { // typeClientHello
		tlsProxy.logger.Printf("TLS request from %s: did not get ClientHello\n",
			downstream.RemoteAddr())
		downstream.Close()
		return
	}

	m := new(clientHelloMsg)
	if !m.unmarshal(rest) {
		tlsProxy.logger.Printf("TLS request from %s: error parsing ClientHello\n",
			downstream.RemoteAddr())
		downstream.Close()
		return
	}
	if m.serverName == "" {
		tlsProxy.logger.Printf("TLS request from %s: error: no server name found\n",
			downstream.RemoteAddr())
		downstream.Close()
		return
	}
	target := m.serverName + ":443" // XXX should use our local port number instead?

	if util.ManyGlob(tlsProxy.config.Upstreams, target) == false {
		tlsProxy.logger.Printf("TLS request from %s: backend \"%s\" not allowed\n",
			downstream.RemoteAddr(), target)
		downstream.Close()
		return
	}
	upstream, err := net.Dial("tcp", target)
	if err != nil {
		tlsProxy.logger.Printf("TLS request from %s: error connecting to backend \"%s\": %s\n",
			downstream.RemoteAddr(), target, err)
		downstream.Close()
		return
	}
	tlsProxy.logger.Printf("TLS request from %s: connected to backend \"%s\"\n",
		downstream.RemoteAddr(), target)

	util.SetDeadlineSeconds(upstream, tlsProxy.config.Deadline)

	if _, err = upstream.Write(append(append(append(firstByte, versionBytes...), restLengthBytes...), rest...)); err != nil {
		tlsProxy.logger.Printf("TLS request from %s: error writing to backend \"%s\": %s\n",
			downstream.RemoteAddr(), target, err)
		downstream.Close()
		upstream.Close()
		return
	}
	// reset current deadlines
	util.SetDeadlineSeconds(upstream, 0)
	util.SetDeadlineSeconds(downstream, 0)

	go util.CopyAndCloseWithIdleTimeout(upstream, downstream, tlsProxy.config.Idle)
	go util.CopyAndCloseWithIdleTimeout(downstream, upstream, tlsProxy.config.Idle)
}

// eof
