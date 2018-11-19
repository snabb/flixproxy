Flixproxy
=========

Flixproxy implements DNS, HTTP and HTTPS/TLS proxies needed for proxying
Netflix connections:

 - DNS proxy with spoofing capability.

 - HTTP proxy which uses the "Host:" header to determine the backend.

 - TLS (HTTPS) proxy which uses the Server Name Indication (SNI) extension
   in the ClientHello TLS packet to determine the backend.

You may be able to use this software to circumvent geoblocking:
1. Setup this proxy in a virtual machine in the desired location.
2. Specify the proxy IP address as the DNS server address in your Smart TV, computer,
router, DHCP or somewhere else.

This software does not work with devices which do not support Server Name
Indication (SNI) extension in their SSL/TLS client implementation.

The Git repository is located at: https://github.com/snabb/flixproxy


Acknowledgements
----------------

Flixproxy requires the following external Go libraries:

- Miek Gieben, [github.com/miekg/dns](https://github.com/miekg/dns)
- Gustavo Niemeyer, [gopkg.in/yaml.v2](https://github.com/go-yaml/yaml)
- Alex Ogier, [github.com/ogier/pflag](https://github.com/ogier/pflag)
- Alan Shreve, [gopkg.in/inconshreveable/log15.v2](https://github.com/inconshreveable/log15)
- Ryan Uber, [github.com/ryanuber/go-glob](https://github.com/ryanuber/go-glob)

Thanks!


License
-------

Copyright © 2015 Janne Snabb <snabb AT epipe.com>

Flixproxy is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Flixproxy is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Flixproxy. If not, see <http://www.gnu.org/licenses/>.

