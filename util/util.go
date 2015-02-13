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
	"github.com/ryanuber/go-glob"
	"io"
)

func ManyGlob(globs []string, str string) bool {
        for _, g := range globs {
                if glob.Glob(g, str) {
                        return true
                }
        }
        return false
}

func CopyAndClose(dst io.WriteCloser, src io.Reader) {
        io.Copy(dst, src)
        dst.Close()
}

// eof
