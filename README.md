## IPv6 Proxy Server

Create your own IPv6 backconnect proxy server with only one script on any Linux distribution. Any number of random IPs on the subnet, ideal for parsing and traffic arbitrage (Google/Facebook/Youtube/Instagram and many others support IPv6).

Buy & ask questions & get help in telegram: [@just_temp](https://t.me/just_temp)

### Tutorial

Assuming you already have an entire IPv6 subnet (/48 or /64) routed to your server.

Just download the script, set execute mode to it and run:

```bash
#sudo su
chmod +x ipv6proxyserver-install.sh
./ipv6proxyserver-install.sh -s 64 -c 100 -u username -p password -t http
```

Uncomment first line or run all commands with `sudo` if you`re not under root.

**Command line arguments:**

- `-s` - Fully dedicated for your server ipv6 [subnet](https://docs.netgate.com/pfsense/en/latest/network/ipv6/subnets.html), script supports 48 or 64
- `-c` - The total number of proxies you want to have (from 1 to 10000)
- `-t` - Proxies type - `http` or `socks5`. Default `http`, if no value provided
- `-u` - All proxies auth login
- `-p` - All proxies auth password