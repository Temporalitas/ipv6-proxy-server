#!/bin/bash
# Script must be running from root
if [ "$EUID" -ne 0 ];
  then echo "Please run as root";
  exit 1;
fi;

# Program help info for users
usage() { echo "Usage: $0 [-s | --subnet <32|48|64> proxy subnet (default 64)] 
                          [-c | --proxy-count <number> count of proxies] 
                          [-u | --username <string> proxy auth username] 
                          [-p | --password <string> proxy password] 
                          [-t | --proxies-type <http|socks5> result proxies type (default http)]
                          [-r | --rotating-interval <0-59> proxies extarnal address rotating time in minutes (default 0, disabled)]
                          [-m | --ipv6-mask <string> constant ipv6 address mask, to which the rotated part is added (or gateaway)
                                use only if the gateway is different from the subnet address]
                          [-l | --localhost <bool> allow connections only for localhost (backconnect on 127.0.0.1)]
                          [--start-port <5000-65536> start port for backconnect ipv4 (default 30000)]
                          " 1>&2; exit 1; }

options=$(getopt -o lhs:c:u:p:t:r:m: --long help,localhost,subnet:,proxy-count:,username:,password:,proxies-type:,rotating-interval:,ipv6-mask:,start-port: -- "$@")

# Throw error and chow help message if user don`t provide any arguments
if [ $? != 0 ] ; then echo "Error: no arguments provided. Terminating..." >&2 ; usage ; fi;

#  Parse command line options
eval set -- "$options"

# Set default values for optional arguments
subnet=64
proxies_type="http"
start_port=30000
rotating_interval=0
use_localhost=false

while true; do
  case "$1" in
    -h | --help ) usage; shift ;;
    -s | --subnet ) subnet="$2"; shift 2 ;;
    -c | --proxy-count ) proxy_count="$2"; shift 2 ;;
    -u | --username ) user="$2"; shift 2 ;;
    -p | --password ) password="$2"; shift 2 ;;
    -t | --proxies-type ) proxies_type="$2"; shift 2 ;;
    -r | --rotating-interval ) rotating_interval="$2"; shift 2;;
    -m | --ipv6-mask ) subnet_mask="$2"; shift 2;;
    -l | --localhost ) use_localhost=true; shift ;;
    --start-port ) start_port="$2"; shift 2;;
    -- ) shift; break ;;
    * ) break ;;
  esac
done

# Check validity of user provided arguments
re='^[0-9]+$'
if ! [[ $proxy_count =~ $re ]] ; then
	echo "Error: Argument -c (proxy count) must be a positive integer number" 1>&2;
	usage;
fi;

if [ -z $user ] || [ -z $password ] ; then
	echo "Error: user and password for proxy is required (specify '--username' and '--password' startup parameters)" 1>&2;
	usage;
fi;

if [ $proxies_type != "http" ] && [ $proxies_type != "socks5" ] ; then
  echo "Error: invalid value of '-t' (proxy type) parameter" 1>&2;
  usage;
fi;

if [ $subnet != 64 ] && [ $subnet != 48 ] && [ $subnet != 32 ]; then
  echo "Error: invalid value of '-s' (subnet) parameter" 1>&2;
  usage;
fi;

if [ $rotating_interval -lt 0 ] || [ $rotating_interval -gt 59 ]; then
  echo "Error: invalid value of '-r' (proxy external ip rotating interval) parameter" 1>&2;
  usage;
fi;

if [ $start_port -lt 5000 ] || (($start_port - $proxy_count > 65536 )); then
  echo "Wrong '--start-port' parameter value, it must be more than 5000 and '--start-port' + '--proxy-count' must be lower than 65536,
because Linux has only 65536 potentially ports" 1>&2;
  usage;
fi;

if [ -z $subnet_mask ]; then 
  blocks_count=$((($subnet / 16) - 1));
  subnet_mask="$(ip -6 addr|awk '{print $2}'|grep -m1 -oP '^(?!fe80)([0-9a-fA-F]{1,4}:){'$blocks_count'}[0-9a-fA-F]{1,4}'|cut -d '/' -f1)";
fi;

# Check is ipv6 enabled or not
if test -f /proc/net/if_inet6; then
	echo "IP v6 interface is enabled";
else
	echo "Error: inet6 (ipv6) interface is not enabled. Enable IP v6 on your system." 1>&2;
	exit 1;
fi;

# Install required libraries
apt update
apt install make g++ wget curl cron -y

# Enable sysctl options for rerouting and bind ips from subnet to default interface
interface_name="$(ip -br l | awk '$1 !~ "lo|vir|wl" { print $1}')"
cat >> /etc/sysctl.conf << EOF
net.ipv6.conf.$interface_name.proxy_ndp=1
net.ipv6.conf.all.proxy_ndp=1
net.ipv6.conf.default.forwarding=1
net.ipv6.conf.all.forwarding=1
net.ipv6.ip_nonlocal_bind = 1
EOF
sysctl -p

# Define all needed paths to scripts / configs / etc
cd ~
user_home_dir="$(pwd)"
# Path to dir with all proxies info
proxy_dir="$user_home_dir/proxyserver"
# Path to file with config for backconnect proxy server
proxyserver_config_path="$proxy_dir/3proxy/3proxy.cfg"
# Path to file with all result (external) ipv6 addresses
random_ipv6_list_file="$proxy_dir/ipv6.list"
# Script on server startup (generate random ids and run proxy daemon)
startup_script_path="$proxy_dir/proxy-startup.sh"

# Get external server ip for backconnect
external_ipv4="$(curl https://ipinfo.io/ip)"
# Use localhost ipv5 address as backconnect for proxy if user want local proxy
localhost_ipv4="127.0.0.1"
backconnect_ipv4=$([ "$use_localhost" == true ] && echo "$localhost_ipv4" || echo "$external_ipv4")

# Execute all command in user home/proxyserver directory, so switch to this folder
if [ -d $proxy_dir ] && [ "$(ls -A $proxy_dir)" ]; then echo "Error: directory for proxyserver already exists and not empty" 1>&2; exit 1; fi;
mkdir $proxy_dir && cd $proxy_dir

# Install proxy server
wget https://github.com/3proxy/3proxy/archive/refs/tags/0.9.4.tar.gz
tar -xf 0.9.4.tar.gz
mv 3proxy-0.9.4 3proxy

# Build proxy server
cd 3proxy
make -f Makefile.Linux
cd ..

# Add main script that runs proxy server and rotates external ip's, if server is already running
cat > $startup_script_path << EOF
#!/bin/bash

# Close 3proxy daemon, if it's working
ps -ef | awk '/[3]proxy/{print \$2}' | while read -r pid; do
  kill \$pid
done

# Remove old random ip list before create new one
if test -f $random_ipv6_list_file; 
then
  # Remove old ips from interface
  for ipv6_address in \$(cat ${random_ipv6_list_file}); do ip -6 addr del \${ipv6_address} dev ${interface_name};done;
  rm $random_ipv6_list_file; 
fi;

# Array with allowed symbols in hex (in ipv6 addresses)
array=( 1 2 3 4 5 6 7 8 9 0 a b c d e f )

# Generate random hex symbol
function rh () { echo \${array[\$RANDOM%16]}; }

rnd_subnet_ip () {
  echo -n $subnet_mask;
  symbol=$subnet
  while (( \$symbol < 128)); do
    if ((\$symbol % 16 == 0)); then echo -n :; fi;
    echo -n \$(rh);
    let "symbol += 4";
  done;
  echo ;
}

# Temporary variable to count generated ip's in cycle
count=1

# Generate random 'proxy_count' ipv6 of specified subnet and write it to 'ip.list' file
while [ "\$count" -le $proxy_count ]
do
  rnd_subnet_ip >> $random_ipv6_list_file;
	let "count += 1";
done;

cat >  $proxyserver_config_path  << EOFSUB
daemon
nserver 1.1.1.1
maxconn 200
nscache 65536
timeouts 1 5 30 60 180 1800 15 60
setgid 65535
setuid 65535
flush
auth strong
users ${user}:CL:${password}
allow ${user}

EOFSUB

# Add all ipv6 backconnect proxy with random adresses in proxy server startup config
port=$start_port
count=1
for random_ipv6_address in \$(cat $random_ipv6_list_file); do
    if [ "$proxies_type" = "http" ]; then proxy_startup_depending_on_type="proxy -6 -n -a"; else proxy_startup_depending_on_type="socks -6 -a"; fi;
    echo "\$proxy_startup_depending_on_type -p\$port -i$backconnect_ipv4 -e\$random_ipv6_address" >> $proxyserver_config_path
    ((port+=1))
    ((count+=1))
    if [ \$count -eq 10001 ]; then
        exit
    fi
done

# Script that adds all random ipv6 to default interface and runs backconnect proxy server
ulimit -n 600000
ulimit -u 600000
for ipv6_address in \$(cat ${random_ipv6_list_file}); do ip -6 addr add \${ipv6_address} dev ${interface_name};done;
${user_home_dir}/proxyserver/3proxy/bin/3proxy ${proxyserver_config_path}
exit 0
EOF
chmod +x $startup_script_path

# Add startup script to cron (job sheduler) to restart proxy server after reboot and rotate proxy pool
cat > "proxy-server.cron" << EOF
@reboot $startup_script_path
EOF
if [ $rotating_interval -ne 0 ]; then echo "*/$rotating_interval * * * * $startup_script_path" >> "proxy-server.cron"; fi;
crontab "proxy-server.cron"

/bin/bash $startup_script_path

exit 0