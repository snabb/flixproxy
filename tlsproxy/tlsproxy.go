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
	"gopkg.in/inconshreveable/log15.v2"
	"io"
	"net"
)

type TLSProxy struct {
	config Config
	access access.Checker
	logger log15.Logger
}

type Config struct {
	Listen    string
	Upstreams []string
	Deadline  int64
	Idle      int64
}

func New(config Config, access access.Checker, logger log15.Logger) (tlsProxy *TLSProxy) {
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
		tlsProxy.logger.Crit("listen tcp error", "listen", tlsProxy.config.Listen, "err", err)
		return
	}
	tlsProxy.logger.Info("listening", "listen", tlsProxy.config.Listen)

	for {
		conn, err := listener.Accept()
		if err != nil {
			tlsProxy.logger.Error("accept error", "listen", tlsProxy.config.Listen, "err", err)
		}
		if tlsProxy.access.AllowedAddr(conn.RemoteAddr()) {
			go tlsProxy.handleTLSConnection(conn)
		} else {
			tlsProxy.logger.Warn("access denied", "src", conn.RemoteAddr())
			go conn.Close()
		}
	}
}

func (tlsProxy *TLSProxy) handleTLSConnection(downstream net.Conn) {
	util.SetDeadlineSeconds(downstream, tlsProxy.config.Deadline)

	logger := tlsProxy.logger.New("src", downstream.RemoteAddr())

	firstByte := make([]byte, 1)
	_, err := io.ReadFull(downstream, firstByte)
	if err != nil {
		if netError, ok := err.(net.Error); ok && netError.Timeout() {
			logger.Info("timeout reading first byte")
		} else {
			logger.Error("error reading first byte", "err", err)
		}
		downstream.Close()
		return
	}
	if firstByte[0] != 0x16 { // recordTypeHandshake
		logger.Error("record type not handshake", "fistbyte", firstByte)
		downstream.Close()
		return
	}

	versionBytes := make([]byte, 2)
	_, err = io.ReadFull(downstream, versionBytes)
	if err != nil {
		logger.Error("error reading version bytes", "err", err)
		downstream.Close()
		return
	}
	if versionBytes[0] < 3 || (versionBytes[0] == 3 && versionBytes[1] < 1) {
		logger.Error("SSL < 3.1 not supported", "versionbytes", versionBytes)
		downstream.Close()
		return
	}

	restLengthBytes := make([]byte, 2)
	_, err = io.ReadFull(downstream, restLengthBytes)
	if err != nil {
		logger.Error("error reading restLength bytes", "err", err)
		downstream.Close()
		return
	}
	restLength := int(restLengthBytes[0])<<8 + int(restLengthBytes[1])

	rest := make([]byte, restLength)
	_, err = io.ReadFull(downstream, rest)
	if err != nil {
		logger.Error("error reading rest of bytes", "err", err)
		downstream.Close()
		return
	}
	if len(rest) == 0 || rest[0] != 1 { // typeClientHello
		logger.Error("did not get ClientHello")
		downstream.Close()
		return
	}

	m := new(clientHelloMsg)
	if !m.unmarshal(rest) {
		logger.Error("error parsing ClientHello")
		downstream.Close()
		return
	}
	if m.serverName == "" {
		logger.Error("no server name found")
		downstream.Close()
		return
	}
	target := m.serverName + ":443" // XXX should use our local port number instead?

	logger = logger.New("backend", target)

	if util.ManyGlob(tlsProxy.config.Upstreams, target) == false {
		logger.Error("backend not allowed")
		downstream.Close()
		return
	}
	upstream, err := net.Dial("tcp", target)
	if err != nil {
		logger.Error("error connecting to backend", "err", err)
		downstream.Close()
		return
	}
	logger.Debug("connected to backend")

	util.SetDeadlineSeconds(upstream, tlsProxy.config.Deadline)

	if _, err = upstream.Write(append(append(append(firstByte, versionBytes...), restLengthBytes...), rest...)); err != nil {
		logger.Error("error writing to backend", "err", err)
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
