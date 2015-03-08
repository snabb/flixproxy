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
	"gopkg.in/inconshreveable/log15.v2"
	"strconv"
	"strings"
)

type DNSProxy struct {
	config Config
	access access.Checker
	logger log15.Logger
}

type Config struct {
	Id        string
	Listen    string
	Acl       string
	Forwarder string
	Spoof     rrSlice
}

type rrSlice struct {
	rrs     map[string][]dns.RR
	wildRrs map[string][]dns.RR
}

func (spoof *rrSlice) unmarshalAny(spoofString string) (err error) {
	spoof.rrs = make(map[string][]dns.RR)
	spoof.wildRrs = make(map[string][]dns.RR)

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
			return err
		}
		key := strings.ToLower(rr.Header().Name)

		if strings.Contains(key, "*") {
			spoof.wildRrs[key] = append(spoof.wildRrs[key], rr)
		} else {
			spoof.rrs[key] = append(spoof.rrs[key], rr)
		}
	}
	return err
}

func (spoof *rrSlice) UnmarshalYAML(unmarshal func(v interface{}) error) (err error) {
	var spoofString string
	if err = unmarshal(&spoofString); err != nil {
		return err
	}
	return spoof.unmarshalAny(spoofString)
}

func (spoof *rrSlice) UnmarshalTOML(d interface{}) (err error) {
	spoofString, ok := d.(string)
	if !ok {
		return errors.New("Expected string")
	}
	return spoof.unmarshalAny(spoofString)
}

func New(config Config, access access.Checker, logger log15.Logger) (dnsProxy *DNSProxy) {
	if config.Id != "" {
		logger = logger.New("id", config.Id)
	}
	dnsProxy = &DNSProxy{
		config: config,
		access: access,
		logger: logger,
	}
	go func() {
		logger.Info("starting udp listener", "listen", config.Listen)
		if err := dns.ListenAndServe(config.Listen, "udp", dnsProxy); err != nil {
			logger.Crit("listen udp error", "listen", config.Listen, "err", err)
		}
	}()
	go func() {
		logger.Info("starting tcp listener", "listen", config.Listen)
		if err := dns.ListenAndServe(config.Listen, "tcp", dnsProxy); err != nil {
			logger.Crit("listen tcp error", "listen", config.Listen, "err", err)
		}
	}()

	return
}

func (dnsProxy *DNSProxy) Stop() {
	// something
}

func makeAnswerMessage(req *dns.Msg, rr []dns.RR) (m *dns.Msg) {
	m = new(dns.Msg)
	m.SetReply(req)
	m.RecursionAvailable = true
	m.Answer = rr
	return m
}

func (dnsProxy *DNSProxy) checkVersionQuestion(req *dns.Msg) (answer *dns.Msg) {
	q := req.Question[0]
	qname := strings.ToLower(q.Name)

	if q.Qclass == dns.ClassCHAOS && q.Qtype == dns.TypeTXT &&
		(qname == "version.bind." || qname == "version.server.") {

		rr := dns.RR(&dns.TXT{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassCHAOS,
				Ttl:    3600,
			},
			Txt: []string{"Flixproxy"},
		})
		return makeAnswerMessage(req, []dns.RR{rr})
	}
	return nil
}

func selectAnswers(q dns.Question, rr []dns.RR) (answer []dns.RR) {
	for _, r := range rr {
		if (q.Qclass == r.Header().Class &&
			q.Qtype == r.Header().Rrtype) ||
			(q.Qclass == r.Header().Class &&
				q.Qtype == dns.TypeANY) {

			a := dns.Copy(r)
			a.Header().Name = q.Name
			answer = append(answer, a)
		}
	}
	return answer
}

func (dnsProxy *DNSProxy) getQuestionAnswer(q dns.Question) (answer []dns.RR) {
	qKey := strings.ToLower(q.Name)

	if rr, ok := dnsProxy.config.Spoof.rrs[qKey]; ok {
		return selectAnswers(q, rr)
	}
	for key, rr := range dnsProxy.config.Spoof.wildRrs {
		if glob.Glob(key, qKey) {
			return selectAnswers(q, rr)
		}
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

func questionString(q dns.Question) string {
	c, ok := dns.ClassToString[q.Qclass]
	if !ok {
		c = strconv.Itoa(int(q.Qclass))
	}
	t, ok := dns.TypeToString[q.Qtype]
	if !ok {
		t = strconv.Itoa(int(q.Qtype))
	}
	return c + "·" + t + "·" + q.Name
}

func (dnsProxy *DNSProxy) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	var response *dns.Msg
	var err error
	logger := dnsProxy.logger.New("src", w.RemoteAddr())

	if len(req.Question) == 0 {
		logger.Debug("empty question")
		response = new(dns.Msg)
		response.SetReply(req)
	} else if len(req.Question) > 1 {
		logger.Error("wrong number of questions", "n", len(req.Question))
		response = new(dns.Msg)
		response.SetRcode(req, dns.RcodeFormatError)
	} else if response = dnsProxy.checkVersionQuestion(req); response != nil {
		logger.Debug("local answer", "question", questionString(req.Question[0]))
	} else if !dnsProxy.access.AllowedAddr(w.RemoteAddr()) {
		logger.Warn("access denied", "question", questionString(req.Question[0]))
		response = new(dns.Msg)
		response.SetRcode(req, dns.RcodeRefused)
	} else if response = dnsProxy.getMessageReply(req); response != nil {
		logger.Debug("local answer", "question", questionString(req.Question[0]))
	} else {
		c := new(dns.Client)
		response, _, err = c.Exchange(req, dnsProxy.config.Forwarder)
		if err == nil {
			logger.Debug("remote answer", "question", questionString(req.Question[0]))
		} else {
			logger.Error("remote error", "question", questionString(req.Question[0]), "err", err)
			response = new(dns.Msg)
			response.SetRcode(req, dns.RcodeServerFailure)
		}
	}
	w.WriteMsg(response)
}

// eof
