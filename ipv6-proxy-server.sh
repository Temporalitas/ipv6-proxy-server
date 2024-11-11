#!/bin/bash
# Script must be running from root
if [ "$EUID" -ne 0 ];
  then echo "Please run as root";
  exit 1;
fi;

# Program help info for users
function usage() { echo "Usage: $0 [-s | --subnet <16|32|48|64|80|96|112> proxy subnet (default 64)] 
                          [-c | --proxy-count <number> count of proxies] 
                          [-u | --username <string> proxy auth username] 
                          [-p | --password <string> proxy password]
                          [--random <bool> generate random username/password for each IPv4 backconnect proxy instead of predefined (default false)] 
                          [-t | --proxies-type <http|socks5> result proxies type (default http)]
                          [-r | --rotating-interval <0-59> rotating time of external proxies address in minutes (default 0, disabled)]
                          [--rotate-every-request <bool> use random external address for every request (--rotating-interval will be ignored)]
                          [--start-port <5000-65536> start port for backconnect ipv4 (default 30000)]
                          [-l | --localhost <bool> allow connections only for localhost (backconnect on 127.0.0.1)]
                          [-f | --backconnect-proxies-file <string> path to file, in which backconnect proxies list will be written
                                when proxies start working (default \`~/proxyserver/backconnect_proxies.list\`)]                                                     
                          [-m | --ipv6-mask <string> constant ipv6 address mask, to which the rotated part is added (or gateaway)
                                use only if the gateway is different from the subnet address]
                          [-i | --interface <string> full name of ethernet interface, on which IPv6 subnet was allocated
                                automatically parsed by default, use ONLY if you have non-standard/additional interfaces on your server]
                          [-b | --backconnect-ip <string> server IPv4 backconnect address for proxies
                                automatically parsed by default, use ONLY if you have non-standard ip allocation on your server]
                          [--allowed-hosts <string> allowed hosts or IPs (3proxy format), for example "google.com,*.google.com,*.gstatic.com"
                                if at least one host is allowed, the rest are banned by default]
                          [--denied-hosts <string> banned hosts or IP addresses in quotes (3proxy format)]
                          [--uninstall <bool> disable active proxies, uninstall server and clear all metadata]
                          [--info <bool> print info about running proxy server]
                          " 1>&2; exit 1; }

options=$(getopt -o lhs:c:u:p:t:r:m:f:i:b: --long help,rotate-every-request,localhost,random,uninstall,info,subnet:,proxy-count:,username:,password:,proxies-type:,rotating-interval:,ipv6-mask:,interface:,start-port:,backconnect-proxies-file:,backconnect-ip:,allowed-hosts:,denied-hosts: -- "$@")

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
use_random_auth=false
uninstall=false
try_rotate_every_request=false
rotate_every_request=false
print_info=false
backconnect_proxies_file="default"
# Global network inteface name
interface_name="$(ip -br l | awk '$1 !~ "lo|vir|wl|@NONE" { print $1 }' | awk 'NR==1')"
# Log file for script execution
script_log_file="/var/tmp/ipv6-proxy-server-logs.log"
backconnect_ipv4=""
subnet_mask=""

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
    -b | --backconnect-ip ) backconnect_ipv4="$2"; shift 2;;
    -f | --backconnect_proxies_file ) backconnect_proxies_file="$2"; shift 2;;
    -i | --interface ) interface_name="$2"; shift 2;;
    -l | --localhost ) use_localhost=true; shift ;;
    --allowed-hosts ) allowed_hosts="$2"; shift 2;;
    --denied-hosts ) denied_hosts="$2"; shift 2;;
    --uninstall ) uninstall=true; shift ;;
    --info ) print_info=true; shift ;;
    --start-port ) start_port="$2"; shift 2;;
    --random ) use_random_auth=true; shift ;;
    --rotate-every-request ) try_rotate_every_request=true; shift ;;
    -- ) shift; break ;;
    * ) break ;;
  esac
done

function log_err(){
  echo $1 1>&2;
  echo -e "$1\n" &>> $script_log_file;
}

function log_err_and_exit(){
  log_err "$1";
  exit 1;
}

function log_err_print_usage_and_exit(){
  log_err "$1";
  usage;
}

function is_valid_ip(){
  if [[ "$1" =~ ^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$ ]]; then return 0; else return 1; fi;
}

function is_auth_used(){
  if [ -z $user ] && [ -z $password] && [ $use_random_auth = false ]; then false; return; else true; return; fi;
}

function check_startup_parameters(){
  # Check validity of user provided arguments
  re='^[0-9]+$'
  if ! [[ $proxy_count =~ $re ]] ; then
    log_err_print_usage_and_exit "Error: Argument -c (proxy count) must be a positive integer number";
  fi;

  if ([ -z $user ] || [ -z $password ]) && is_auth_used && [ $use_random_auth = false ]; then
    log_err_print_usage_and_exit "Error: user and password for proxy with auth is required (specify both '--username' and '--password' startup parameters)";
  fi;

  if ([[ -n $user ]] || [[ -n $password ]]) && [ $use_random_auth = true ]; then
    log_err_print_usage_and_exit "Error: don't provide user or password as arguments, if '--random' flag is set.";
  fi;

  if [ $proxies_type != "http" ] && [ $proxies_type != "socks5" ] ; then
    log_err_print_usage_and_exit "Error: invalid value of '-t' (proxy type) parameter";
  fi;

  if [ $(expr $subnet % 4) != 0 ]; then
    log_err_print_usage_and_exit "Error: invalid value of '-s' (subnet) parameter, must be divisible by 4";
  fi;

  if [ $rotating_interval -lt 0 ] || [ $rotating_interval -gt 59 ]; then
    log_err_print_usage_and_exit "Error: invalid value of '-r' (proxy external ip rotating interval) parameter";
  fi;

  if [ $start_port -lt 5000 ] || (($start_port - $proxy_count > 65536 )); then
    log_err_print_usage_and_exit "Wrong '--start-port' parameter value, it must be more than 5000 and '--start-port' + '--proxy-count' must be lower than 65536,
  because Linux has only 65536 potentially ports";
  fi;

  if [ ! -z $backconnect_ipv4 ]; then 
    if ! is_valid_ip $backconnect_ipv4; then
      log_err_and_exit "Error: ip provided in 'backconnect-ip' argument is invalid. Provide valid IP or don't use this argument"
    fi;
  fi;

  if [ -n "$allowed_hosts" ] && [ -n "$denied_hosts" ]; then
    log_err_print_usage_and_exit "Error: if '--allow-hosts' is specified, you cannot use '--deny-hosts', the rest that isn't allowed is denied by default";
  fi;

  if cat /sys/class/net/$interface_name/operstate 2>&1 | grep -q "No such file or directory"; then
    log_err_print_usage_and_exit "Incorrect ethernet interface name \"$interface_name\", provide correct name using parameter '--interface'";
  fi;
}

# Define all needed paths to scripts / configs / etc
bash_location="$(which bash)"
# Get user home dir absolute path
cd ~
user_home_dir="$(pwd)"
# Path to dir with all proxies info
proxy_dir="$user_home_dir/proxyserver"
# Path to file with config for backconnect proxy server
proxyserver_config_path="$proxy_dir/3proxy/3proxy.cfg"
# Path to file with nformation about running proxy server in user-readable format
proxyserver_info_file="$proxy_dir/running_server.info"
# Path to file with all result (external) ipv6 addresses
random_ipv6_list_file="$proxy_dir/ipv6.list"
# Path to file that used to check are proxy router via ndppd or not
ndppd_routing_file="$proxy_dir/ndppd.routed"
# Path to file with proxy random usernames/password
random_users_list_file="$proxy_dir/random_users.list"
# Define correct path to file with backconnect proxies list, if it isn't defined by user
if [[ $backconnect_proxies_file == "default" ]]; then backconnect_proxies_file="$proxy_dir/backconnect_proxies.list"; fi;
# Script on server startup (generate random ids and run proxy daemon)
startup_script_path="$proxy_dir/proxy-startup.sh"
# Cron config path (start proxy server after linux reboot and IPs rotations)
cron_script_path="$proxy_dir/proxy-server.cron"
# Last opened port for backconnect proxy
last_port=$(($start_port + $proxy_count - 1));
# Proxy credentials - username and password, delimited by ':', if exist, or empty string, if auth == false
credentials=$(is_auth_used && [[ $use_random_auth == false ]] && echo -n ":$user:$password" || echo -n "");

function is_proxyserver_installed(){
  if [ -d $proxy_dir ] && [ "$(ls -A $proxy_dir)" ]; then return 0; fi;
  return 1;
}

function is_proxyserver_running(){
  if ps aux | grep -q $proxyserver_config_path; then return 0; else return 1; fi;
}

function is_package_installed(){
  if [ $(dpkg-query -W -f='${Status}' $1 2>/dev/null | grep -c "ok installed") -eq 0 ]; then return 1; else return 0; fi;
}

function is_ndppd_running(){
  # Use regex for ndppd to remove grep command output in `ps aux`
  if ps aux | grep -q "[n]dppd"; then return 0; else return 1; fi;
}

function is_ndppd_routing_working(){
  if ! is_ndppd_running; then 
    log_err "ndppd isn't running. You cannot use every-request rotation.";
    return 1;
  fi;
  if ! is_package_installed "curl"; then install_package "curl"; fi;
  if [[ $(cat /proc/sys/net/ipv6/conf/$interface_name/proxy_ndp) != 1 ]]; then
    log_err "proxy_ndp not set, you cannot use every-request rotation before it.";
    return 1;
  fi;

  # Use this ip (subnet mask then zeros then 5252) to test, can we access websites with it or not
  random_ipv6_for_test=$subnet_mask::5252;

  # Try many websites to verify that we can use this IP, because some sites can be down
  if curl -m 5 -s --interface $random_ipv6_for_test ipv6.ip.sb | grep -q $random_ipv6_for_test; then return 0; fi;
  if curl -m 5 -s --interface $random_ipv6_for_test https://whatismyv6.com | grep -q $random_ipv6_for_test; then return 0; fi;
  if curl -m 5 -s --interface $random_ipv6_for_test http://ip6only.me | grep -q $random_ipv6_for_test; then return 0; fi;
  if curl -m 5 -s --interface $random_ipv6_for_test https://myipv6.is | grep -q $random_ipv6_for_test; then return 0; fi;
  if curl -m 5 -s --interface $random_ipv6_for_test https://dnschecker.org/whats-my-ip-address.php | grep -q $random_ipv6_for_test; then return 0; fi;

  log_err "Cannot connect to at least one website to verify, that test IPv6 address for ndppd subnet is available."
  return 1;
}

function create_random_string(){
  tr -dc A-Za-z0-9 </dev/urandom | head -c $1 ; echo ''
}

function kill_3proxy(){
  ps -ef | awk '/[3]proxy/{print $2}' | while read -r pid; do
    kill $pid
  done;
}

function remove_ipv6_addresses_from_iface(){
  if grep -q "false" $ndppd_routing_file || ! test -s $ndppd_routing_file && test -s $random_ipv6_list_file; then
    # Remove old ips from interface
    for ipv6_address in $(cat $random_ipv6_list_file); do ip -6 addr del $ipv6_address dev $interface_name; done;
    rm $random_ipv6_list_file; 
  fi;
}

function get_subnet_mask(){
  if [ -z $subnet_mask ]; then
    # If we parse addresses from iface and want to use lower subnets, we need to clean existing proxy from interface before parsing
    if is_proxyserver_running; then kill_3proxy; fi;
    if is_proxyserver_installed; then remove_ipv6_addresses_from_iface; fi;
    
    full_blocks_count=$(($subnet / 16));
    # Full external ipv6 address, allocated to the interface
    ipv6=$(ip -6 addr | awk '{print $2}' | grep -m1 -oP '^(?!fe80)([0-9a-fA-F]{1,4}:)+[0-9a-fA-F]{1,4}' | cut -d '/' -f1);

    subnet_mask=$(echo $ipv6 | grep -m1 -oP '^(?!fe80)([0-9a-fA-F]{1,4}:){'$(($full_blocks_count-1))'}[0-9a-fA-F]{1,4}');
    if [ $(expr $subnet % 16) -ne 0 ]; then
      # Get last "uncomplete" block: if we want /68 subnet, get block from 64 to 80
      block_part=$(echo $ipv6 | awk -v block=$(($full_blocks_count + 1)) -F ':' '{print $block}' | tr -d ' ');
      # Because leading zeros can be skipped in the block, we need to add them if needed
      while ((${#block_part} < 4)); do block_part="0$block_part"; done;
      # Get part of block needed for subnet mask: if we want /72 subnet, we get 2 symbols - (72 (subnet) - 64 (full 4 blocks)) / 4 (2^4) in one hex digit
      symbols_to_include=$(echo $block_part | head -c $(($(expr $subnet % 16) / 4)));
      subnet_mask="$subnet_mask:$symbols_to_include";
    fi;
  fi;

  echo $subnet_mask;
}

function delete_file_if_exists(){
  if test -f $1; then rm $1; fi;
}

function install_package(){
  if ! is_package_installed $1; then
    apt install $1 -y &>> $script_log_file;
    if ! is_package_installed $1; then
      log_err_and_exit "Error: cannot install \"$1\" package";
    fi;
  fi;
}

function get_backconnect_ipv4(){
  if $use_localhost; then echo "127.0.0.1"; return; fi;
  if [ ! -z "$backconnect_ipv4" -a "$backconnect_ipv4" != " " ]; then echo $backconnect_ipv4; return; fi;

  local maybe_ipv4=$(ip addr show $interface_name | awk '$1 == "inet" {gsub(/\/.*$/, "", $2); print $2}')
  if is_valid_ip $maybe_ipv4; then echo $maybe_ipv4; return; fi;

  if ! is_package_installed "curl"; then install_package "curl"; fi;

  (maybe_ipv4=$(curl https://ipinfo.io/ip)) &> /dev/null
  if is_valid_ip $maybe_ipv4; then echo $maybe_ipv4; return; fi;

  log_err_and_exit "Error: curl package not installed and cannot parse valid IP from interface info";
}


function check_ipv6(){
  # Check is ipv6 enabled or not
  if test -f /proc/net/if_inet6; then
	  echo "IPv6 interface is enabled";
  else
	  log_err_and_exit "Error: inet6 (ipv6) interface is not enabled. Enable IP v6 on your system.";
  fi;

  if [[ $(ip -6 addr show scope global) ]]; then
    echo "IPv6 global address is allocated on server successfully";
  else
    log_err_and_exit "Error: IPv6 global address is not allocated on server, allocate it or contact your VPS/VDS support.";
  fi;

  local ifaces_config="/etc/network/interfaces";
  if [ ! -f $ifaces_config ]; then log_err "Potential error: interfaces config ($ifaces_config) doesn't exist"; fi;
    
  if grep 'inet6' $ifaces_config > /dev/null; then
    echo "Network interfaces for IPv6 configured correctly";
  else
    log_err "Potential error: $ifaces_config has no inet6 (IPv6) configuration.";
  fi;

  if [[ $(ping6 -c 1 google.com) != *"Network is unreachable"* ]] &> /dev/null; then 
    echo "Test ping google.com using IPv6 successfully";
  else
    log_err_and_exit "Error: test ping google.com through IPv6 failed, network is unreachable.";
  fi; 

}

# Install required libraries
function install_requred_packages(){
  apt update &>> $script_log_file;

  requred_packages=("make" "g++" "wget" "curl" "cron" "ndppd" "procps");
  for package in ${requred_packages[@]}; do install_package $package; done;

  echo -e "\nAll required packages installed successfully";
}

function install_3proxy(){

  mkdir $proxy_dir && cd $proxy_dir

  echo -e "\nDownloading proxy server source...";
  ( # Install proxy server
  wget https://github.com/3proxy/3proxy/archive/refs/tags/0.9.4.tar.gz &> /dev/null
  tar -xf 0.9.4.tar.gz
  rm 0.9.4.tar.gz
  mv 3proxy-0.9.4 3proxy) &>> $script_log_file
  echo "Proxy server source code downloaded successfully";

  echo -e "\nStart building proxy server execution file from source...";
  # Build proxy server
  cd 3proxy
  make -f Makefile.Linux &>> $script_log_file;
  if test -f "$proxy_dir/3proxy/bin/3proxy"; then
    echo "Proxy server builded successfully"
  else
    log_err_and_exit "Error: proxy server build from source code failed."
  fi;
  cd ..
}

function configure_ipv6(){
  # Enable sysctl options for rerouting and bind ips from subnet to default interface
  required_options=("conf.$interface_name.proxy_ndp" "conf.all.proxy_ndp" "conf.default.forwarding" "conf.all.forwarding" "ip_nonlocal_bind");
  for option in ${required_options[@]}; do
    full_option="net.ipv6.$option=1";
    if ! cat /etc/sysctl.conf | grep -v "#" | grep -q $full_option; then echo $full_option >> /etc/sysctl.conf; fi;
  done;
  sysctl -p &>> $script_log_file;

  if [[ $(cat /proc/sys/net/ipv6/conf/$interface_name/proxy_ndp) == 1 ]] && [[ $(cat /proc/sys/net/ipv6/ip_nonlocal_bind) == 1 ]]; then 
    echo "IPv6 network sysctl data configured successfully";
  else
    cat /etc/sysctl.conf &>> $script_log_file;
    log_err_and_exit "Error: cannot configure IPv6 config";
  fi;
}

function configure_ndppd(){
  # Add neighbour route to redirect connections from any address from the subnet to interface and ndppd can handle them
  ip route add local $subnet_mask::/$subnet dev $interface_name;

  cat > /etc/ndppd.conf <<-EOF
  route-ttl 30000

  proxy $interface_name {
    router no
    timeout 500
    ttl 30000

    rule $subnet_mask::/$subnet {
        static
    }
  }
EOF
  
  service ndppd restart;

  systemctl is-active --quiet ndppd | echo "ndppd is up and running";
}

function add_to_cron(){
  delete_file_if_exists $cron_script_path;

  # Add startup script to cron (job sheduler) to restart proxy server after reboot and rotate proxy pool
  echo "@reboot $bash_location $startup_script_path" > $cron_script_path;
  if [ $rotating_interval -ne 0 ]; then echo "*/$rotating_interval * * * * $bash_location $startup_script_path" >> "$cron_script_path"; fi;

  # Add existing cron rules (not related to this proxy server) to cron script, so that they are not removed
  # https://unix.stackexchange.com/questions/21297/how-do-i-add-an-entry-to-my-crontab
  crontab -l | grep -v $startup_script_path >> $cron_script_path;

  crontab $cron_script_path;
  systemctl restart cron;

  if crontab -l | grep -q $startup_script_path; then 
    echo "Proxy startup script added to cron autorun successfully";
  else
    log_err "Warning: adding script to cron autorun failed.";
  fi;
}

function remove_from_cron(){
  # Delete all occurencies of proxy script in crontab
  crontab -l | grep -v $startup_script_path > $cron_script_path;
  crontab $cron_script_path;
  systemctl restart cron;

  if crontab -l | grep -q $startup_script_path; then
    log_err "Warning: cannot delete proxy script from crontab";
  else
    echo "Proxy script deleted from crontab successfully";
  fi;
}

function generate_random_users_if_needed(){
  # No need to generate random usernames and passwords for proxies, if auth=none or one username/password for all proxies provided
  if $use_random_auth; then return; fi;
  delete_file_if_exists $random_users_list_file;
  
  for i in $(seq 1 $proxy_count); do 
    echo $(create_random_string 8):$(create_random_string 8) >> $random_users_list_file;
  done;
}

function create_startup_script(){
  delete_file_if_exists $startup_script_path;

  is_auth_used;
  local use_auth=$?;

  is_ndppd_routing_working;
  local can_route_via_ndppd=$?

  if $try_rotate_every_request; then
    if [ $can_route_via_ndppd -eq 0 ]; then
      echo "Rotation for every request is possible, starting config generation..."
      rotate_every_request=true;
    else
      log_err_and_exit "IP rotation for every request isn't prossible for your server. Check logs, maybe it's a problem with your VPS provider";
    fi;
  fi;

  # Add main script that runs proxy server and rotates external ip's, if server is already running
  cat > $startup_script_path <<-EOF
  #!$bash_location

  # Remove leading whitespaces in every string in text
  function dedent() {
    local -n reference="\$1"
    reference="\$(echo "\$reference" | sed 's/^[[:space:]]*//')"
  }

  # Save old 3proxy daemon pids, if exists
  proxyserver_process_pids=(\`pgrep -f [3]proxy\`)

  # Save old IPv6 addresses in temporary file to delete from interface after rotating
  old_ipv6_list_file="$random_ipv6_list_file.old";
  if test -f $random_ipv6_list_file; 
    then cp $random_ipv6_list_file \$old_ipv6_list_file; 
    rm $random_ipv6_list_file;
  fi;

  old_ndppd_routing_file="$ndppd_routing_file.old";
  if test -f $ndppd_routing_file;
    then cp $ndppd_routing_file \$old_ndppd_routing_file;
  fi;
  if [ $can_route_via_ndppd -eq 0 ]; then echo "true" > $ndppd_routing_file; else echo "false" > $ndppd_routing_file; fi; 

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

  immutable_config_part="daemon
    nserver 1.1.1.1
    maxconn 200
    nscache 65536
    timeouts 1 5 30 60 180 1800 15 60
    setgid 65535
    setuid 65535"

  auth_part="auth iponly"
  if [ $use_auth -eq 0 ]; then
    auth_part="
      auth strong
      users $user:CL:$password"
  fi;
  
  if [ -n "$denied_hosts" ]; then 
    access_rules_part="
      deny * * $denied_hosts
      allow *"
  elif [ -n "$allowed_hosts" ]; then
    access_rules_part="
      allow * * $allowed_hosts
      deny *"
  else
    access_rules_part="allow *"
  fi;
  if $rotate_every_request; then 
    access_rules_part="
      \${access_rules_part}
      parent 1000 extip $subnet_mask::/$subnet 0"
  fi;
    

  dedent immutable_config_part;
  dedent auth_part;
  dedent access_rules_part;

  echo "\$immutable_config_part"\$'\n'"\$auth_part"\$'\n'"\$access_rules_part"  > $proxyserver_config_path;

  # Add all ipv6 backconnect proxy with random adresses in proxy server startup config
  port=$start_port
  count=0
  if [ "$proxies_type" = "http" ]; then proxy_startup_depending_on_type="proxy -6 -n -a"; else proxy_startup_depending_on_type="socks -6 -a"; fi;
  if [ $use_random_auth = true ]; then readarray -t proxy_random_credentials < $random_users_list_file; fi;
  while [ "\$count" -le $proxy_count ]; do
      if [ $use_random_auth = true ]; then
        IFS=":";
        read -r username password <<< "\${proxy_random_credentials[\$count]}";
        echo "flush" >> $proxyserver_config_path;
        echo "users \$username:CL:\$password" >> $proxyserver_config_path;
        echo "\$access_rules_part" >> $proxyserver_config_path;
        IFS=$' \t\n';
      fi;
      if $rotate_every_request; then
        echo "\$proxy_startup_depending_on_type -p\$port -i$backconnect_ipv4" >> $proxyserver_config_path;
      else
        random_gateway_ipv6=\$(rnd_subnet_ip)
        echo "\$random_gateway_ipv6" >> $random_ipv6_list_file;
        echo "\$proxy_startup_depending_on_type -p\$port -i$backconnect_ipv4 -e\$random_gateway_ipv6" >> $proxyserver_config_path;
      fi;
      ((port+=1))
      ((count+=1))
  done

  # Script that adds all random ipv6 to default interface and runs backconnect proxy server
  ulimit -n 600000
  ulimit -u 600000
  if [ $can_route_via_ndppd -eq 1 ]; then 
    for ipv6_address in \$(cat ${random_ipv6_list_file}); do ip -6 addr add \$ipv6_address dev $interface_name; done; 
  fi;
  ${user_home_dir}/proxyserver/3proxy/bin/3proxy ${proxyserver_config_path}

  # Kill old 3proxy daemon, if it's working
  for pid in "\${proxyserver_process_pids[@]}"; do
    kill \$pid;
  done;

  # Remove old random ip list after running new 3proxy instance
  if  grep -q "false" \$old_ndppd_routing_file || ! test -s \$old_ndppd_routing_file && [ -s \$old_ipv6_list_file ]; then
    for ipv6_address in \$(cat \$old_ipv6_list_file); do ip -6 addr del \$ipv6_address dev $interface_name; done;
    rm \$old_ipv6_list_file; 
  fi;

  exit 0;
EOF
  
}

function close_ufw_backconnect_ports(){
  if ! is_package_installed "ufw" || [ $use_localhost = true ] || ! test -f $backconnect_proxies_file; then return; fi;

  local first_opened_port=$(head -n 1 $backconnect_proxies_file | awk -F ':' '{print $2}');
  local last_opened_port=$(tail -n 1 $backconnect_proxies_file | awk -F ':' '{print $2}');

  ufw delete allow $first_opened_port:$last_opened_port/tcp >> $script_log_file;
  ufw delete allow $first_opened_port:$last_opened_port/udp >> $script_log_file;

  if ufw status | grep -qw $first_opened_port:$last_opened_port; then
    log_err "Cannot delete UFW rules for backconnect proxies";
  else
    echo "UFW rules for backconnect proxies cleared successfully";
  fi;
}

function open_ufw_backconnect_ports(){
  close_ufw_backconnect_ports;

  # No need open ports if backconnect proxies on localhost
  if $use_localhost; then return; fi;

  if ! is_package_installed "ufw"; then echo "Firewall not installed, ports for backconnect proxy opened successfully"; return; fi;

  if ufw status | grep -qw active; then
    ufw allow $start_port:$last_port/tcp >> $script_log_file;
    ufw allow $start_port:$last_port/udp >> $script_log_file;

    if ufw status | grep -qw $start_port:$last_port; then
      echo "UFW ports for backconnect proxies opened successfully";
    else
      log_err $(ufw status);
      log_err_and_exit "Cannot open ports for backconnect proxies, configure ufw please";
    fi;

  else
    echo "UFW protection disabled, ports for backconnect proxy opened successfully";
  fi;
}

function run_proxy_server(){
  if [ ! -f $startup_script_path ]; then log_err_and_exit "Error: proxy startup script doesn't exist."; fi;

  chmod +x $startup_script_path;
  $bash_location $startup_script_path;
  if is_proxyserver_running; then 
    echo -e "\nIPv6 proxy server started successfully. Backconnect IPv4 is available from $backconnect_ipv4:$start_port$credentials to $backconnect_ipv4:$last_port$credentials via $proxies_type protocol";
    echo "You can copy all proxies (with credentials) in this file: $backconnect_proxies_file";
  else
    log_err_and_exit "Error: cannot run proxy server";
  fi;
}

function write_backconnect_proxies_to_file(){
  delete_file_if_exists $backconnect_proxies_file;

  local proxy_credentials=$credentials;
  if ! touch $backconnect_proxies_file &> $script_log_file; then 
    echo "Backconnect proxies list file path: $backconnect_proxies_file" >> $script_log_file;
    log_err "Warning: provided invalid path to backconnect proxies list file";
    return;
  fi;

  if $use_random_auth; then 
    local proxy_random_credentials;
    local count=0;
    readarray -t proxy_random_credentials < $random_users_list_file;
  fi;

  for port in $(eval echo "{$start_port..$last_port}"); do
    if $use_random_auth; then 
      proxy_credentials=":${proxy_random_credentials[$count]}";
      ((count+=1))
    fi;
    echo "$backconnect_ipv4:$port$proxy_credentials" >> $backconnect_proxies_file;
  done;
}

function write_proxyserver_info(){
  delete_file_if_exists $proxyserver_info_file;

  cat > $proxyserver_info_file <<-EOF
User info:
  Proxy count: $proxy_count
  Proxy type: $proxies_type
  Proxy IP: $backconnect_ipv4
  Proxy ports: between $start_port and $last_port
  Auth: $(if is_auth_used; then if [ $use_random_auth = true ]; then echo "random user/password for each proxy"; else echo "user - $user, password - $password"; fi; else echo "disabled"; fi;)
  Rules: $(if ([ -n "$denied_hosts" ] || [ -n "$allowed_hosts" ]); then if [ -n "$denied_hosts" ]; then echo "denied hosts - $denied_hosts, all others are allowed"; else echo "allowed hosts - $allowed_hosts, all others are denied"; fi; else echo "no rules specified, all hosts are allowed"; fi;)
  File with backconnect proxy list: $backconnect_proxies_file


EOF

  cat >> $proxyserver_info_file <<-EOF
Technical info:
  Subnet: /$subnet
  Subnet mask: $subnet_mask
  File with generated IPv6 gateway addresses: $(if $rotate_every_request; then echo "No file specified, rotating every request with different random IP"; else echo "$random_ipv6_list_file"; fi;)
  $(if [ $rotating_interval -ne 0 ]; then echo "Rotating interval: every $rotating_interval minutes"; else if $rotate_every_request; then echo "Rotating: every request"; else echo "Rotating: disabled"; fi; fi;)
EOF
}

if $print_info; then
  if ! is_proxyserver_installed; then log_err_and_exit "Proxy server isn't installed"; fi;
  if ! is_proxyserver_running; then log_err_and_exit "Proxy server isn't running. You can check log of previous run attempt in $script_log_file"; fi;
  if ! test -f $proxyserver_info_file; then log_err_and_exit "File with information about running proxy server not found"; fi;

  cat $proxyserver_info_file;
  exit 0;
fi;

if $uninstall; then
  if ! is_proxyserver_installed; then log_err_and_exit "Proxy server is not installed"; fi;
  
  remove_from_cron;
  kill_3proxy;
  remove_ipv6_addresses_from_iface;
  close_ufw_backconnect_ports;
  rm -rf $proxy_dir;
  delete_file_if_exists $backconnect_proxies_file;
  echo -e "\nIPv6 proxy server successfully uninstalled. If you want to reinstall, just run this script again.";
  exit 0;
fi;


delete_file_if_exists $script_log_file;
check_startup_parameters;
check_ipv6;
backconnect_ipv4=$(get_backconnect_ipv4);
subnet_mask=$(get_subnet_mask)
if is_proxyserver_installed; then
  echo -e "Proxy server already installed, reconfiguring:\n";
else
  configure_ipv6;
  install_requred_packages;
  install_3proxy;
  configure_ndppd;
fi;
generate_random_users_if_needed;
create_startup_script;
add_to_cron;
open_ufw_backconnect_ports;
run_proxy_server;
write_backconnect_proxies_to_file;
write_proxyserver_info;

exit 0