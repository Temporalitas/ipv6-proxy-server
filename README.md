## IPv6 Proxy Server

Create your own IPv6 backconnect proxy server with only one script on any Linux distribution. Any number of random IPs on the subnet, ideal for parsing and traffic arbitrage (Google/Facebook/Youtube/Instagram and many others support IPv6).

Buy & ask questions & get help in telegram: [@just_temp](https://t.me/just_temp)

### Tutorial

Assuming you already have an entire IPv6 subnet (/48 or /64) routed to your server.

Just download the script, set execute mode to it and run:

```bash
#sudo su
chmod +x ipv6proxyserver-install.sh
./ipv6proxyserver-install.sh -s 64 -c 100 -u username -p password -t http -r 10
```

Uncomment first line or run all commands with `sudo` if you`re not under root.

**Command line arguments:**

- `-s` or `--subnet` - IPv6  [subnet](https://docs.netgate.com/pfsense/en/latest/network/ipv6/subnets.html), fully dedicated for your server. `48` or `64`, default `64`
- `-c` or `--proxy-count` - The total number of proxies you want to have (from 1 to 10000)
- `-t` or `--proxies-type` - Proxies type - `http` or `socks5`. Default `http`, if no value provided
- `-u` or `--username` - All proxies auth login (required)
- `-p` or `--password` - All proxies auth password (required)
- `--start-port` - backconnect IPv4 start port. If you create 1500 proxies and `start-port` is `20000`, and server external IPv4 is, e.g,`180.113.14.28` you can connect to proxies using `180.113.14.28:20000`, `180.113.14.28:20001` and so on until `180.113.14.28:21500`
- `-r` or `--rotating-interval` - rotation interval of entire proxy pool in minutes. At the end of each interval, output (external IPv6) addresses of all proxies are changed and  proxy server is restarted, which breaks existing connections for a few seconds. Default value - `0` (rotating disabled)