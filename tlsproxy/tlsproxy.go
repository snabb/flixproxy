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
	"log"
	"net"
	"strings"
)

type TLSProxy struct {
	config Config
	access access.Checker
	logger *log.Logger
}

type Config struct {
	Listen    string
	Upstreams []string
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
		if tlsProxy.access.AllowedNetAddr(conn.RemoteAddr()) {
			go tlsProxy.handleTLSConnection(conn)
		} else {
			go conn.Close()
		}
	}
}

func (tlsProxy *TLSProxy) handleTLSConnection(downstream net.Conn) {
	firstByte := make([]byte, 1)
	_, err := downstream.Read(firstByte)
	if err != nil {
		tlsProxy.logger.Printf("TLS request from %s: error reading first byte: %s\n",
			downstream.RemoteAddr(), err)
		downstream.Close()
		return
	}
	if firstByte[0] != 0x16 {
		tlsProxy.logger.Printf("TLS request from %s: not TLS\n", downstream.RemoteAddr())
		downstream.Close()
		return
	}

	versionBytes := make([]byte, 2)
	_, err = downstream.Read(versionBytes)
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
	_, err = downstream.Read(restLengthBytes)
	if err != nil {
		tlsProxy.logger.Printf("TLS request from %s: error reading restLength bytes: %s\n",
			downstream.RemoteAddr(), err)
		downstream.Close()
		return
	}
	restLength := (int(restLengthBytes[0]) << 8) + int(restLengthBytes[1])

	rest := make([]byte, restLength)
	_, err = downstream.Read(rest)
	if err != nil {
		tlsProxy.logger.Printf("TLS request from %s: error reading rest of bytes: %s\n",
			downstream.RemoteAddr(), err)
		downstream.Close()
		return
	}
	current := 0

	handshakeType := rest[0]
	current += 1
	if handshakeType != 0x1 {
		tlsProxy.logger.Printf("TLS request from %s: error: not ClientHello\n",
			downstream.RemoteAddr())
		downstream.Close()
		return
	}
	// Skip over another length
	current += 3
	// Skip over protocolversion
	current += 2
	// Skip over random number
	current += 4 + 28
	// Skip over session ID
	sessionIDLength := int(rest[current])
	current += 1
	current += sessionIDLength

	cipherSuiteLength := (int(rest[current]) << 8) + int(rest[current+1])
	current += 2
	current += cipherSuiteLength

	compressionMethodLength := int(rest[current])
	current += 1
	current += compressionMethodLength

	if current > restLength {
		tlsProxy.logger.Printf("TLS request from %s: error: no extensions\n",
			downstream.RemoteAddr())
		downstream.Close()
		return
	}

	// Skip over extensionsLength
	// extensionsLength := (int(rest[current]) << 8) + int(rest[current + 1])
	current += 2

	hostname := ""
	for current < restLength && hostname == "" {
		extensionType := (int(rest[current]) << 8) + int(rest[current+1])
		current += 2

		extensionDataLength := (int(rest[current]) << 8) + int(rest[current+1])
		current += 2

		if extensionType == 0 {
			// Skip over number of names as we're assuming there's just one
			current += 2

			nameType := rest[current]
			current += 1
			if nameType != 0 {
				tlsProxy.logger.Printf("TLS request from %s: error: nameType = %d\n",
					downstream.RemoteAddr(), nameType)
				downstream.Close()
				return
			}
			nameLen := (int(rest[current]) << 8) + int(rest[current+1])
			current += 2
			hostname = string(rest[current : current+nameLen])
		}

		current += extensionDataLength
	}
	if hostname == "" {
		tlsProxy.logger.Printf("TLS request from %s: error: no hostname found\n",
			downstream.RemoteAddr())
		downstream.Close()
		return
	}
	if strings.Index(hostname, ":") == -1 {
		hostname = hostname + ":443"
	}
	if util.ManyGlob(tlsProxy.config.Upstreams, hostname) == false {
		tlsProxy.logger.Printf("TLS request from %s: backend \"%s\" not allowed\n",
			downstream.RemoteAddr(), hostname)
		downstream.Close()
		return
	}
	upstream, err := net.Dial("tcp", hostname)
	if err != nil {
		tlsProxy.logger.Printf("TLS request from %s: error connecting to backend \"%s\": %s\n",
			downstream.RemoteAddr(), hostname, err)
		downstream.Close()
		return
	}
	tlsProxy.logger.Printf("TLS request from %s: connected to backend \"%s\"\n",
		downstream.RemoteAddr(), hostname)

	upstream.Write(firstByte)
	upstream.Write(versionBytes)
	upstream.Write(restLengthBytes)
	upstream.Write(rest)

	go util.CopyAndClose(upstream, downstream)
	go util.CopyAndClose(downstream, upstream)
}

// eof
