//
// util.go
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

package util

import (
	"bufio"
	"github.com/ryanuber/go-glob"
	"gopkg.in/inconshreveable/log15.v2"
	"io"
	"net"
	"time"
)

func ManyGlob(globs []string, str string) (matched bool) {
	for _, g := range globs {
		if glob.Glob(g, str) {
			return true
		}
	}
	return false
}

func SetDeadlineSeconds(conn net.Conn, seconds int64) (err error) {
	if seconds == 0 {
		return conn.SetDeadline(time.Time{})
	}
	return conn.SetDeadline(time.Now().Add(time.Duration(seconds) * time.Second))
}

func SetReadDeadlineSeconds(conn net.Conn, seconds int64) (err error) {
	if seconds == 0 {
		return conn.SetReadDeadline(time.Time{})
	}
	return conn.SetReadDeadline(time.Now().Add(time.Duration(seconds) * time.Second))
}

func SetWriteDeadlineSeconds(conn net.Conn, seconds int64) (err error) {
	if seconds == 0 {
		return conn.SetWriteDeadline(time.Time{})
	}
	return conn.SetWriteDeadline(time.Now().Add(time.Duration(seconds) * time.Second))
}

func CopyWithIdleTimeout(dst net.Conn, src net.Conn, timeout int64) (written int64, err error) {
	buf := make([]byte, 32*1024)
	for {
		SetReadDeadlineSeconds(src, timeout)
		nr, er := src.Read(buf)
		if nr > 0 {
			SetWriteDeadlineSeconds(dst, timeout)
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er == io.EOF {
			break
		}
		if er != nil {
			err = er
			break
		}
	}
	return written, err
}

func ReadBufferedBytes(rd *bufio.Reader) (buf []byte, err error) {
	count := rd.Buffered()
	if count == 0 {
		return []byte{}, nil
	}
	buf = make([]byte, count)
	_, err = io.ReadFull(rd, buf)
	return buf, err
}

type Handler interface {
	HandleConn(*net.TCPConn)
}

func ListenAndServe(listen string, handler Handler, logger log15.Logger) {
	logger = logger.New("listen", listen)
	logger.Info("starting tcp listener")
	laddr, err := net.ResolveTCPAddr("tcp", listen)
	if err != nil {
		logger.Crit("listen address error", "err", err)
		return
	}
	listener, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		logger.Crit("listen tcp error", "err", err)
		return
	}

	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			logger.Error("accept error", "err", err)
			continue
		}
		go handler.HandleConn(conn)
	}
}

// the following is from https://gist.github.com/jbardin/821d08cb64c01c84b81a

func Proxy(srvConn, cliConn *net.TCPConn, timeout int64) {
	// channels to wait on the close event for each connection
	serverClosed := make(chan struct{}, 1)
	clientClosed := make(chan struct{}, 1)

	go broker(srvConn, cliConn, clientClosed, timeout)
	go broker(cliConn, srvConn, serverClosed, timeout)

	// wait for one half of the proxy to exit, then trigger a shutdown of
	// the other half by calling CloseRead(). This will break the read
	// loop in the broker and allow us to fully close the connection
	// cleanly without a "use of closed network connection" error.
	var waitFor chan struct{}
	select {
	case <-clientClosed:
		// the client closed first and any more packets from the
		// server aren't useful, so we can optionally SetLinger(0)
		// here to recycle the port faster.
		srvConn.SetLinger(0)
		srvConn.CloseRead()
		waitFor = serverClosed
	case <-serverClosed:
		cliConn.CloseRead()
		waitFor = clientClosed
	}

	// Wait for the other connection to close.
	// This "waitFor" pattern isn't required, but gives us a way to track
	// the connection and ensure all copies terminate correctly; we can
	// trigger stats on entry and deferred exit of this function.
	<-waitFor
}

// This does the actual data transfer.
// The broker only closes the Read side.
func broker(dst, src net.Conn, srcClosed chan struct{}, timeout int64) {
	// We can handle errors in a finer-grained manner by inlining
	// io.Copy (it's simple, and we drop the ReaderFrom or WriterTo
	// checks for net.Conn->net.Conn transfers, which aren't needed).
	// This would also let us adjust buffersize.
	_, err := CopyWithIdleTimeout(dst, src, timeout)

	if err != nil {
		// log.Printf("Copy error: %s", err)
	}
	if err := src.Close(); err != nil {
		// log.Printf("Close error: %s", err)
	}
	srcClosed <- struct{}{}
}

// eof
