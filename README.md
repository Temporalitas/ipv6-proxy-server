## IPv6 Proxy Server [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Create your own IPv6 backconnect proxy server with only one script on any Linux distribution. Any number of random IPs on the subnet, ideal for parsing and traffic arbitrage (Google/Facebook/Youtube/Instagram and many others support IPv6).

Ask questions [in issues](https://github.com/Temporalitas/ipv6-proxy-server/issues), if you have some.

### Tutorial

Assuming you already have an entire IPv6 subnet (/48 or /64) routed to your server.

Just run:

```bash
#sudo su
wget https://raw.githubusercontent.com/Temporalitas/ipv6-proxy-server/master/ipv6-proxy-server.sh && chmod +x ipv6-proxy-server.sh
./ipv6-proxy-server.sh -s 64 -c 100 -u username -p password -t http -r 10
```

Uncomment first line or run all commands with `sudo` if you`re not under root.



If script already installed, you can just run one command to reconfigure parameters, for example:

```bash
./ipv6-proxy-server.sh -s 64 -c 20 -u username2 -p password2 -t socks5 -r 2
```

Old instance will be disabled and new starts without reinstallation very quickly.



If you want to uninstall proxy server, just run:

```bash
./ipv6-proxy-server.sh --uninstall
```

Proxy server will stopped, all configuration files, firewalls, shedulers and so on will be reset to initial state.



**Command line arguments:**

- `-s` or `--subnet` - IPv6 [subnet](https://docs.netgate.com/pfsense/en/latest/network/ipv6/subnets.html), fully allocated on your server. Any subnet divisible by 4 (for example, `48` or `56`), default `64`
- `-c` or `--proxy-count` - The total number of proxies you want to have (from 1 to 10000)
- `-t` or `--proxies-type` - Proxies type - `http` or `socks5`. Default `http`, if no value provided
- `-u` or `--username` - All proxies auth login
- `-p` or `--password` - All proxies auth password (if you specify neither username not password, proxy will run without authentication)
- `--rotate-every-request` - bool parameter without value, if used, for every request to each proxy you will get different gateway IP from your IPv6 subnet. Doesn't work on all VPS. If configuration isn't possible, it will exit with an error
- `--random` - bool parameter without value, if used, each backconnect proxy will have random username and password, that will be written in backconnect proxies file (`-f` argument)
- `--start-port` - backconnect IPv4 start port. If you create 1500 proxies and `start-port` is `20000`, and server external IPv4 is, e.g,`180.113.14.28` you can connect to proxies using `180.113.14.28:20000`, `180.113.14.28:20001` and so on until `180.113.14.28:21500`
- `-r` or `--rotating-interval` - rotation interval of entire proxy pool in minutes. At the end of each interval, output (external IPv6) addresses of all proxies are changed and proxy server is restarted, which breaks existing connections for a few seconds. From 0 to 59, default value - `0` (rotating disabled)
- `--allowed-hosts` - list of allowed hosts, to which user can connect via proxy (comma-separated, without spaces, for example - `"google.com,*.google.com,fb.com"`). All other hosts will be denied, if this parameter is provided
- `--denied-hosts` - list of denied hosts (comma-separated, without spaces, for example - `"google.com,*.google.com,fb.com"`). All others hosts will be allowed, if this parameter is provided
- `-l` or `--localhost` - bool parameter without value, if used, all backconnect proxy will be available only on localhost (`127.0.0.1:30000` instead of `180.113.14.28:30000`)
- `-b` or `--backconnect-ip` - server IPv4 backconnect address for proxies, use ONLY if script cannot parse IP correctly and your server has non-standard IP configuration
- `-f` or `--backconnect-proxies-file` - path to file, in which backconnect proxies list will be written when proxies start working (default `~/proxyserver/backconnect_proxies.list`). You can just copy all proxies from this file and use them in your soft as list of IPv6 proxies.
- `-m` or `--ipv6-mask` - first blocks on server subnet, unchanged part, use ONLY if script cannot parse ipv6 mask automatically. For example, if the external ipv6 address on server is `2a03:6f01:5::1da6` and you want to use entire /64 subnet, script cannot parse ipv6 gateway because of address zero-field replacement with `::`. Real mask for /64 subnet is first four blocks - `2a03:6f01:5:0`
- `-i` or `--interface` - ethernet interface name, to which IPv6 subnet is allocated and where all proxies will be raised. Automatically parsed from system info by default, use ONLY if you have non-standard/additional interfaces on your server.
- `--uninstall` - uninstall proxy server, you don't need to provide any other parameters with it.
- `--info` - get info about running proxy server (proxy count, rotating, auth, etc.)



**Quick errors FAQ:**

- If your proxies simply don't work, do these few steps and write an issue **only** if none of this worked:
  - Check your logfile: `/var/tmp/ipv6-proxy-server-logs.log` for any error-like messages. If message is related to configuration/subnet allocation, ask your VPS provider. If error message is unclear, write an issue.
  - If there is no errors, run `./ipv6-proxy-server.sh --info`.
  - Check that backconnect addresses parsed correctly (the file name on your server in first step).
  - Check that outgoing IPv6 addresses generated correctly (in `proxyserver/3proxy/3proxy.cfg` file).
  - Check connection from proxy server: select one of outgoing IPv6 addresses from previous step and run command `curl --interface <ipv6-address> <website>`. If it works correctly, but proxy doesn't work - write an issue right now.
  - Check if the site you want to access has an AAAA record in DNS. If no, you cannot reach this site via any IPv6 proxies.
  - Verify that your VPS provider allocated a full IPv6 subnet to the server (DigitalOcean and many other providers don't do this).

### License

[MIT](https://opensource.org/licenses/MIT)
