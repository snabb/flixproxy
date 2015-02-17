Flixproxy
=========

Flixproxy implements DNS, HTTP and HTTPS/TLS proxies needed for proxying
Netflix connections:

 - DNS proxy with spoofing capability.

 - HTTP proxy which uses the "Host:" header to determine the backend.

 - TLS (HTTPS) proxy which uses the Server Name Indication (SNI) extension
   in the ClientHello TLS packet to determine the backend.

You can run this software on a chep VPS in US and get the US version of
Neflix by specifying the Flixproxy VPS IP address as the DNS server address
in your Smart TV, computer, router, DHCP or somewhere else.

This software does not work with devices which do not support Server Name
Indication (SNI) extension in their SSL/TLS client implementation.

The Git repository is located at: https://github.com/snabb/flixproxy


Acknowledgements
----------------

Some ideas and code may have been stolen from:

- Borislav Nikolov, [github.com/jackdoe/cacher](https://github.com/jackdoe/cacher)
- Giles Thomas, [github.com/gpjt/stupid-proxy](https://github.com/gpjt/stupid-proxy)

Flixproxy requires the following external Go libraries:

- Andrew Gallant, [github.com/BurntSushi/toml](https://github.com/BurntSushi/toml)
- Miek Gieben, [github.com/miekg/dns](https://github.com/miekg/dns)
- Alex Ogier, [github.com/ogier/pflag](https://github.com/ogier/pflag)
- Alan Shreve, [github.com/inconshreveable/log15](https://github.com/inconshreveable/log15)
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

