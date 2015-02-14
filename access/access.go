//
// access.go
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

package access

import (
	"errors"
	"net"
)

type Config struct {
	Allow []myIPNet
}

type myIPNet struct {
	*net.IPNet
}

func (myIPNet *myIPNet) UnmarshalTOML(d interface{}) (err error) {
	ipstring, ok := d.(string)
	if !ok {
		return errors.New("Expected array of strings")
	}
	_, myIPNet.IPNet, err = net.ParseCIDR(ipstring)
	return
}

func (config Config) AllowedIP(ip net.IP) bool {
	for _, ipmask := range config.Allow {
		if ipmask.Contains(ip) {
			return true
		}
	}
	return false
}

func (config Config) AllowedAddr(addr net.Addr) bool {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return config.AllowedIP(ip)
	}
	return false
}

type Checker interface {
	AllowedIP(ip net.IP) bool
	AllowedAddr(addr net.Addr) bool
}

// eof
