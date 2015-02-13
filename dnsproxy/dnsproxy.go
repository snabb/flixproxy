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
	"strconv"
	"strings"
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
	if myip.IP = net.ParseIP(ipstring); myip.IP == nil {
		return errors.New("Invalid IP address")
	}
	return nil
}

type Config struct {
	Listen    string
	Forwarder string
	Spoof     rrSlice
}

type rrSlice struct {
	rrs     map[string]dns.RR
	wildRrs map[string]dns.RR
}

func makeKey(rrclass uint16, rrtype uint16, name string) string {
	c, ok := dns.ClassToString[rrclass]
	if !ok {
		c = strconv.Itoa(int(rrclass))
	}
	t, ok := dns.TypeToString[rrtype]
	if !ok {
		t = strconv.Itoa(int(rrtype))
	}
	return c + "\000" + t + "\000" + strings.ToLower(name)
}

func (spoof *rrSlice) UnmarshalTOML(d interface{}) (err error) {
	spoofString, ok := d.(string)
	if !ok {
		return errors.New("Expected string")
	}
	spoof.rrs = make(map[string]dns.RR)
	spoof.wildRrs = make(map[string]dns.RR)

	for _, line := range strings.Split(spoofString, "\n") {
		line = strings.TrimSpace(line)

		if len(line) == 0 {
			continue
		}
		if line[0] == ';' || line[0] == '#' {
			continue
		}

		var rr dns.RR
		if rr, err = dns.NewRR(line); err != nil {
			return
		}
		key := makeKey(rr.Header().Class, rr.Header().Rrtype, strings.Fields(line)[0])

		if strings.Contains(key, "*") {
			spoof.wildRrs[key] = rr
		} else {
			spoof.rrs[key] = rr
		}
	}
	return
}

func New(config Config, access *access.Access, logger *log.Logger) (dnsProxy *DNSProxy) {
	dnsProxy = &DNSProxy{
		config: config,
		access: access,
		logger: logger,
	}
	go func() {
		if err := dns.ListenAndServe(config.Listen, "udp", dnsProxy); err != nil {
			logger.Fatalln("DNS error:", err)
		}
	}()
	go func() {
		if err := dns.ListenAndServe(config.Listen, "tcp", dnsProxy); err != nil {
			logger.Fatalln("DNS error:", err)
		}
	}()

	return
}

func (dnsProxy *DNSProxy) Stop() {
	// something
}

func (dnsProxy *DNSProxy) getQuestionAnswer(q dns.Question) *dns.RR {
	qKey := makeKey(q.Qclass, q.Qtype, q.Name)

	if rr, ok := dnsProxy.config.Spoof.rrs[qKey]; ok {
		rr.Header().Name = q.Name
		return &rr
	}
	for key, rr := range dnsProxy.config.Spoof.wildRrs {
		if glob.Glob(key, qKey) {
			rr.Header().Name = q.Name
			return &rr
		}
	}
	return nil
}

func makeAnswerMessage(req *dns.Msg, rr *dns.RR) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.RecursionAvailable = true
	m.Answer = []dns.RR{*rr}
	return m
}

func (dnsProxy *DNSProxy) checkVersionQuestion(req *dns.Msg) *dns.Msg {
	q := req.Question[0]
	qKey := makeKey(q.Qclass, q.Qtype, q.Name)

	if qKey == "CH\000TXT\000version.bind." ||
		qKey == "CH\000TXT\000version.server." {

		rr := dns.RR(&dns.TXT{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassCHAOS,
				Ttl:    3600,
			},
			Txt: []string{"Flixproxy"},
		})
		return makeAnswerMessage(req, &rr)
	}
	return nil
}

func (dnsProxy *DNSProxy) getMessageReply(req *dns.Msg) *dns.Msg {
	q := req.Question[0]

	if answer := dnsProxy.getQuestionAnswer(q); answer != nil {
		return makeAnswerMessage(req, answer)
	}

	if q.Qtype == dns.TypeAAAA {
		// check if corresponding spoofed A record exists
		q2 := q
		q2.Qtype = dns.TypeA
		if dnsProxy.getQuestionAnswer(q2) != nil {
			// return NXDOMAIN
			// client should retry looking up for TypeA
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeNameError)
			return m
		}
	}
	return nil
}

func (dnsProxy *DNSProxy) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	var response *dns.Msg
	var err error
	if len(req.Question) != 1 {
		dnsProxy.logger.Printf("DNS wrong number of questions from %s: %d\n",
			w.RemoteAddr(), len(req.Question))
		response = new(dns.Msg)
		response.SetRcode(req, dns.RcodeFormatError)
	} else if response = dnsProxy.checkVersionQuestion(req); response != nil {
		dnsProxy.logger.Printf("DNS query from %s \"%s\" local answer: %s\n",
			w.RemoteAddr(), req.Question[0].Name, response.Answer)
	} else if !dnsProxy.access.AllowedNetAddr(w.RemoteAddr()) {
		dnsProxy.logger.Printf("DNS refusing query for \"%s\" from %s\n",
			req.Question[0].Name, w.RemoteAddr())
		response = new(dns.Msg)
		response.SetRcode(req, dns.RcodeRefused)
	} else if response = dnsProxy.getMessageReply(req); response != nil {
		dnsProxy.logger.Printf("DNS query from %s \"%s\" local answer: %s\n",
			w.RemoteAddr(), req.Question[0].Name, response.Answer)
	} else {
		c := new(dns.Client)
		response, _, err = c.Exchange(req, dnsProxy.config.Forwarder)
		if err == nil {
			dnsProxy.logger.Printf("DNS query from %s \"%s\" remote answer: %s\n",
				w.RemoteAddr(), req.Question[0].Name, response.Answer)
		} else {
			dnsProxy.logger.Printf("DNS query from %s \"%s\" remote error: %s\n",
				w.RemoteAddr(), req.Question[0].Name, err)
			response = new(dns.Msg)
			response.SetRcode(req, dns.RcodeServerFailure)
		}
	}
	w.WriteMsg(response)
}

// eof
