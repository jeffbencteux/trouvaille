#!/bin/sh
# Copyright (c) 2023, Jeffrey Bencteux
# All rights reserved.

# This source code is licensed under the GPLv3 license found in the
# LICENSE file in the root directory of this source tree.

# shellcheck disable=SC3043

usage()
{
	echo "Usage: $0 [options]"
	echo "Find network information"
	echo
	echo "arguments:"
	echo "  -i network interface to check"
	echo "  -r read from given pcap instead of live capture"
}

print_good()
{
	printf '\033[1;32m[+]\033[0m %s\n' "$1"
}

print_bad()
{
	printf '\033[1;31m[-]\033[0m %s\n' "$1"
}

print_module()
{
	log ""
	printf '\033[1;33m[%s]\033[0m\n' "$1"
	log ""
}

log()
{
	echo "$1"
}

find_ips_in_range()
{
	local ips="$1"
	local range="$2"
	local grep_pattern="$3"

	ips_in_range=$(echo "$ips" | grepcidr "$range" | grep -Eo --color "$grep_pattern" | sort -u)

	if [ "$ips_in_range" != "" ]; then
		print_good "found IPs for private range $range"
		log ""
		log "$ips_in_range"
		log ""
	fi
}

find_private_ips()
{
	local ips="$1"

	find_ips_in_range "$ips" "10.0.0.0/8" "10.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
	find_ips_in_range "$ips" "172.16.0.0/12" "172.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
	find_ips_in_range "$ips" "192.168.0.0/16" "192.168.[0-9]{1,3}\.[0-9]{1,3}"
}

arp_ip_addresses()
{
	local pcap_path="$1"

	arp_ips=$(tshark -r "$pcap_path" -T fields -e arp.src.proto_ipv4 -e arp.dst.proto_ipv4)

	find_private_ips "$arp_ips"
}

ip_addresses()
{
	print_good "Looking for src and dst addresses in packets"
	local pcap_path="$1"
	ips=$(tshark -r "$pcap_path" -T fields -e ip.src -e ip.dst | uniq)

	find_private_ips "$ips"
}

dhcp_addresses()
{
	print_good "Looking for IP addresses in DHCP"
	local pcap_path="$1"
	local ips

	ips=$(tshark -r "$pcap_path" -T fields -e dhcp.ip.client -e dhcp.option.router -e dhcp.option.requested_ip_address -e dhcp.option.resource_location_server -e dhcp.option.static_route.ip -e dhcp.option.static_route.router -e dhcp.option.value.address -e dhcp.option.dhcp_server_id | uniq)

	find_private_ips "$ips"
}

pcap_dir="."
capture_time="3"

while getopts "i:r:" o; do
	case "${o}" in
		i)
			iface="${OPTARG}"
		;;
		r)
			pcap_path="${OPTARG}"
		;;
		*)
			usage
			exit 1
		;;
	esac
done

if [ "$iface" = "" ] && [ "$pcap_path" = "" ]; then
	print_bad "Interface missing"
	usage
	exit 1
fi

log "Trouvaille"
log ""

if [ "$pcap_path" = "" ]; then
	pcap_path="$pcap_dir/capture.pcap"

	print_good "Capturing packets on $iface for $capture_time seconds"
	sudo timeout "$capture_time" tcpdump -i "$iface" -w "$pcap_path"
else
	print_good "Reading from $pcap_path"
fi

print_module "ARP"
arp_ip_addresses "$pcap_path"

print_module "IP"
ip_addresses "$pcap_path"

print_module "DHCP"
dhcp_addresses "$pcap_path"
