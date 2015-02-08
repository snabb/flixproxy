//
// dnsproxy.go
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

package dnsproxy

import (
	"errors"
	"github.com/miekg/dns"
	"github.com/ryanuber/go-glob"
	"github.com/snabb/flixproxy/access"
	"log"
	"net"
)

type DNSProxy struct {
	config Config
	access *access.Access
	logger *log.Logger
}

type myIP struct {
	net.IP
}

func (myip *myIP) UnmarshalTOML(d interface{}) error {
	ipstring, ok := d.(string)
	if !ok {
		return errors.New("Expected array of strings")
	}
	myip.IP = net.ParseIP(ipstring)
	if myip.IP == nil {
		return errors.New("Invalid IP address")
	}
	return nil
}

type Config struct {
	Listen     string
	Forwarder  string
	SpoofNames []string
	SpoofIP    myIP
	SpoofTTL   uint32
}

func New(config Config, access *access.Access, logger *log.Logger) (dnsproxy *DNSProxy) {
	dnsproxy = &DNSProxy{
		config: config,
		access: access,
		logger: logger,
	}
	go func() {
		if err := dns.ListenAndServe(config.Listen, "udp", dnsproxy); err != nil {
			logger.Fatalln("listen udp "+config.Listen+" error:", err)
		}
	}()
	go func() {
		if err := dns.ListenAndServe(config.Listen, "tcp", dnsproxy); err != nil {
			logger.Fatalln("listen tcp "+config.Listen+" error:", err)
		}
	}()

	return
}

func (dnsproxy *DNSProxy) Stop() {
	// something
}

func (this *DNSProxy) getAnswer(req *dns.Msg) *dns.Msg {
	q := req.Question[0]
	if q.Qclass != dns.ClassINET {
		return nil
	}
	if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
		return nil
	}
	found := false
	for _, name := range this.config.SpoofNames {
		if glob.Glob(name, q.Name) {
			found = true
			break
		}
	}
	if !found {
		return nil
	}
	m := new(dns.Msg)
	if q.Qtype == dns.TypeAAAA {
		// IPv6 is not supported at this time
		m.SetRcode(req, dns.RcodeNameError)
		return m
	}
	m.SetReply(req)
	m.RecursionAvailable = true

	rr := dns.RR_A{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    this.config.SpoofTTL,
		},
		A: this.config.SpoofIP.IP,
	}

	m.Answer = []dns.RR{rr.Copy()}

	return m
}

func (this *DNSProxy) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if !this.access.AllowedNetAddr(w.RemoteAddr()) {
		this.logger.Printf("refusing query for \"%s\" from %s\n",
			req.Question[0].Name, w.RemoteAddr())
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeRefused)
		w.Write(m)
		return
	}
	// support only queries with exactly one question
	if len(req.Question) != 1 {
		this.logger.Printf("wrong number of questions from %s: %d\n",
			w.RemoteAddr(), len(req.Question))
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeFormatError)
		w.Write(m)
	}
	if m := this.getAnswer(req); m != nil {
		this.logger.Printf("query from %s \"%s\" local answer: %s\n",
			w.RemoteAddr(), req.Question[0].Name, m.Answer)
		w.Write(m)
		return
	}
	c := new(dns.Client)
	response, err := c.Exchange(req, this.config.Forwarder)
	if err != nil {
		this.logger.Printf("query from %s \"%s\" remote error: %s\n",
			w.RemoteAddr(), req.Question[0].Name, err)
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		w.Write(m)
		return
	}
	this.logger.Printf("query from %s \"%s\" remote answer: %s\n",
		w.RemoteAddr(), req.Question[0].Name, response.Answer)
	w.Write(response)
}

// eof
