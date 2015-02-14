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
	"io"
	"net"
	"time"
)

func ManyGlob(globs []string, str string) bool {
	for _, g := range globs {
		if glob.Glob(g, str) {
			return true
		}
	}
	return false
}

func SetDeadlineSeconds(conn net.Conn, seconds int64) error {
	if seconds == 0 {
		return conn.SetDeadline(time.Time{})
	}
	return conn.SetDeadline(time.Now().Add(time.Duration(seconds) * time.Second))
}

func SetReadDeadlineSeconds(conn net.Conn, seconds int64) error {
	if seconds == 0 {
		return conn.SetReadDeadline(time.Time{})
	}
	return conn.SetReadDeadline(time.Now().Add(time.Duration(seconds) * time.Second))
}

func SetWriteDeadlineSeconds(conn net.Conn, seconds int64) error {
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

func CopyAndClose(dst io.WriteCloser, src io.Reader) {
	io.Copy(dst, src)
	dst.Close()
}

func CopyAndCloseWithIdleTimeout(dst net.Conn, src net.Conn, timeout int64) {
	CopyWithIdleTimeout(dst, src, timeout)
	dst.Close()
}

func ReadBufferedBytes(rd *bufio.Reader) ([]byte, error) {
	count := rd.Buffered()
	if count == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, count)
	_, err := io.ReadFull(rd, buf)
	return buf, err
}

// eof
