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
	"github.com/ryanuber/go-glob"
	"github.com/snabb/flixproxy/access"
	"io"
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
	TLS       bool
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

func (httpProxy *HTTPProxy) allowedUpstream(str string) bool {
	for _, upstreamGlob := range httpProxy.config.Upstreams {
		if glob.Glob(upstreamGlob, str) {
			return true
		}
	}
	return false
}

func (httpProxy *HTTPProxy) doProxy() {
	listener, err := net.Listen("tcp", httpProxy.config.Listen)
	if err != nil {
		httpProxy.logger.Fatalln("HTTP listen tcp "+
			httpProxy.config.Listen+" error:", err)
		return
	}
	var handle func(net.Conn)
	if httpProxy.config.TLS {
		handle = httpProxy.handleHTTPSConnection
	} else {
		handle = httpProxy.handleHTTPConnection
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			httpProxy.logger.Println("HTTP accept "+
				httpProxy.config.Listen+" error:", err)
		}
		if httpProxy.access.AllowedNetAddr(conn.RemoteAddr()) {
			go handle(conn)
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
	if httpProxy.allowedUpstream(hostname) == false {
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

	go copyAndClose(upstream, reader)
	go copyAndClose(downstream, upstream)
}

func (httpProxy *HTTPProxy) handleHTTPSConnection(downstream net.Conn) {
	firstByte := make([]byte, 1)
	_, err := downstream.Read(firstByte)
	if err != nil {
		httpProxy.logger.Printf("HTTPS request from %s: error reading first byte: %s\n",
			downstream.RemoteAddr(), err)
		downstream.Close()
		return
	}
	if firstByte[0] != 0x16 {
		httpProxy.logger.Printf("HTTPS request from %s: not TLS\n", downstream.RemoteAddr())
		downstream.Close()
		return
	}

	versionBytes := make([]byte, 2)
	_, err = downstream.Read(versionBytes)
	if err != nil {
		httpProxy.logger.Printf("HTTPS request from %s: error reading version bytes: %s\n",
			downstream.RemoteAddr(), err)
		downstream.Close()
		return
	}
	if versionBytes[0] < 3 || (versionBytes[0] == 3 && versionBytes[1] < 1) {
		httpProxy.logger.Printf("HTTPS request from %s: error: SSL < 3.1 not supported\n",
			downstream.RemoteAddr())
		downstream.Close()
		return
	}

	restLengthBytes := make([]byte, 2)
	_, err = downstream.Read(restLengthBytes)
	if err != nil {
		httpProxy.logger.Printf("HTTPS request from %s: error reading restLength bytes: %s\n",
			downstream.RemoteAddr(), err)
		downstream.Close()
		return
	}
	restLength := (int(restLengthBytes[0]) << 8) + int(restLengthBytes[1])

	rest := make([]byte, restLength)
	_, err = downstream.Read(rest)
	if err != nil {
		httpProxy.logger.Printf("HTTPS request from %s: error reading rest of bytes: %s\n",
			downstream.RemoteAddr(), err)
		downstream.Close()
		return
	}
	//	httpProxy.logger.Printf("rest = % x\n", rest)

	current := 0

	handshakeType := rest[0]
	current += 1
	if handshakeType != 0x1 {
		httpProxy.logger.Printf("HTTPS request from %s: error: not ClientHello\n",
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
		httpProxy.logger.Printf("HTTPS request from %s: error: no extensions\n",
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
				httpProxy.logger.Printf("HTTPS request from %s: error: nameType = %d\n",
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
		httpProxy.logger.Printf("HTTPS request from %s: error: no hostname found\n",
			downstream.RemoteAddr())
		downstream.Close()
		return
	}
	if strings.Index(hostname, ":") == -1 {
		hostname = hostname + ":443"
	}
	if httpProxy.allowedUpstream(hostname) == false {
		httpProxy.logger.Printf("HTTPS request from %s: backend \"%s\" not allowed\n",
			downstream.RemoteAddr(), hostname)
		downstream.Close()
		return
	}
	upstream, err := net.Dial("tcp", hostname)
	if err != nil {
		httpProxy.logger.Printf("HTTPS request from %s: error connecting to backend \"%s\": %s\n",
			downstream.RemoteAddr(), hostname, err)
		downstream.Close()
		return
	}
	httpProxy.logger.Printf("HTTPS request from %s: connected to backend \"%s\"\n",
		downstream.RemoteAddr(), hostname)

	upstream.Write(firstByte)
	upstream.Write(versionBytes)
	upstream.Write(restLengthBytes)
	upstream.Write(rest)

	go copyAndClose(upstream, downstream)
	go copyAndClose(downstream, upstream)
}

func copyAndClose(dst io.WriteCloser, src io.Reader) {
	io.Copy(dst, src)
	dst.Close()
}

// eof
