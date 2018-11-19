//
// logging.go
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

package main

import (
	"gopkg.in/inconshreveable/log15.v2"
	"log/syslog"
	"os"
)

type LoggingTarget struct {
	Destination string // filename, stderr, stdout or syslog
	Format      string // logfmt, json or terminal
	Level       string // crit, error, warn, info or debug
}

var syslogPrio = syslog.LOG_INFO | syslog.LOG_USER

func setupLogging(logger log15.Logger, targets []LoggingTarget) {
	var handlers []log15.Handler
	var err error

	for _, tgt := range targets {
		logger := logger.New("destination", tgt.Destination, "format", tgt.Format, "level", tgt.Level)
		level := log15.LvlDebug // default
		if tgt.Level != "" {
			if level, err = log15.LvlFromString(tgt.Level); err != nil {
				logger.Error("invalid log level", "err", err)
			}
		}
		format := log15.LogfmtFormat() // default
		switch tgt.Format {
		case "logfmt":
			format = log15.LogfmtFormat()
		case "json":
			format = log15.JsonFormat()
		case "terminal":
			format = log15.TerminalFormat()
		default:
			logger.Error("invalid log format")
		}
		var handler log15.Handler
		switch tgt.Destination {
		case "stdout":
			handler = log15.StreamHandler(os.Stdout, format)
		case "stderr":
			handler = log15.StreamHandler(os.Stderr, format)
		case "syslog":
			if handler, err = log15.SyslogHandler(syslogPrio, "flixproxy", format); err != nil {
				logger.Error("error opening syslog", "err", err)
				continue
			}
		default:
			if handler, err = log15.FileHandler(tgt.Destination, format); err != nil {
				logger.Error("error opening log file", "err", err)
				continue
			}
		}
		if level != log15.LvlDebug {
			handler = log15.LvlFilterHandler(level, handler)
		}
		handlers = append(handlers, handler)
	}
	var handler log15.Handler
	switch len(handlers) {
	case 0:
		handler = log15.DiscardHandler()
	case 1:
		handler = handlers[0]
	default:
		handler = log15.MultiHandler(handlers...)
	}
	logger.SetHandler(handler)
}

// eof
