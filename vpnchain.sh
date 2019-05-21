#!/bin/bash

#
## OpenVPN Chaining Script by unresolvedsymbol idea originally by TensorTom
##
## Doesn't support IPv6 yet
##
## Psst if you're using this you're probably going to want to use DNSCrypt, Tor, Hostname/MAC randomization, etc...
#

#
## Configuration
#

# TODO User friendly configuration options

# Config array number is used for ordering chain
#config[0]=vpn156329528.ovpn
#config[1]=vpn189006776.ovpn
# If none are set it will scan the vpn folder for ovpn files and randomize them (also chooses a new one if one fails)

configs="vpns"
verbose=1 # OpenVPN verbose level; from 0 to 6
vpngate=1 # Grab VPNs from VPNGate
killswitch=1 # Block traffic when the chain goes down
block_ipv6=1 # Disable IPV6 (to prevent leaks if your VPNs aren't IPv6)
replace_broken=1 # Try to replace VPNs that don't work from configs folder
tor=0 # Connect to first VPN with Tor (not reccomended or tested, just normally use Tor at the end of the chain)

#
## Don't change anything below unless you kow whaat you're doing (says the original creator, who had no clue what he was doing)
#

source "${0%/*}/functions.vpnchain" # Include functions

mkdir -p $configs

# If list doesn't exist or hasn't been updated in an hour
[ $vpngate -gt 0 ] && [[ ! -a vpngate.csv || $(find vpngate.csv -mmin +60 -type f -print) ]] && {
    log info "Downloading VPNs from VPNGate..."
    curl -so vpngate.csv http://www.vpngate.net/api/iphone/ # Download list
    log info "Importing to \"${configs}\"..."
    tail -n+3 vpngate.csv | head -n-1 | awk -F, -v configs="$configs" '{ system("echo \""$15"\" | base64 -di > "configs"/"$1".ovpn"); }' # Import VPNs
    log info "Grabbed $(($(wc -l <vpngate.csv)-3)) VPNs from VPNGate."
}

[ $UID != 0 ] && {
	log error "Please run this script as root."
	exit 1
}

[ "$1" = "flush" ] && {
	firewall flush
	[ $block_ipv6 -gt 0 ] && sysctl -qw net.ipv6.conf.all.disable_ipv6=0
	log info "Killswitch disabled. You are no longer secure!"
	exit
}

[ ! -v config[@] ] && {
    log info "Chain not set, creating from folder..."
	echo -n "Generated chain length: "
	read make_chain
    [[ $make_chain =~ ^-?[0-9]+$ ]] || {
        log error "Invalid input."
        exit 1    
    }
	config=($(get_configs | head -${make_chain}))
    [ ${#config[@]} -ne $make_chain ] && {
        log error "Not enough OpenVPN configurations (.ovpn) found in \"${configs}\"."
        exit 1
    }
}

(( chain_length=${#config[@]}-1 )) # Chain length
tun_array=() # Array of tunnel interfaces

[ $killswitch -gt 0 ] && firewall setup # Setup killswitch if enabled

[ $block_ipv6 -gt 0 ] && sysctl -qw net.ipv6.conf.all.disable_ipv6=1

# Cleanup before exit
trap " on_exit " INT TERM

i=0 # Current VPN in chain to connect
while [ $i -le $chain_length ]; do
	# Clear options
	unset openvpn_options
	
	# Parse VPN's IP from config
	client_remote_ip=$(get_ip ${config[$i]})

	# Get default gateway for routing purposes
	default_gateway=$(ip route show default | cut -d' ' -f3)

	# Check if we don't have last config or if there is only one config set;
	# or else we don't need to provide any route directly to openvpn command. In that case all needed routing is done
	# by vpnchain_helper.sh script
	[ $i = 0 ] && openvpn_options+=" --route $client_remote_ip 255.255.255.255 $default_gateway"

    # Route through Tor if enabled and is entry VPN
	[[ $tor -gt 0 && $i -eq 0 ]] && openvpn_options+=" --socks-proxy 127.0.0.1 9050"

    # Check if last (exit) VPN
	[ $i -eq $chain_length ] && {
		openvpn_up="vpnchain_helper.sh -u -l"
		openvpn_down="vpnchain_helper.sh -d -l"
	} || {
		# For routing purposes we need to get the next VPN's IP
		[ $i -lt $chain_length ] && next_client_remote_ip=$(get_ip ${config[$i+1]}) || unset next_client_remote_ip

		openvpn_up="vpnchain_helper.sh -u $next_client_remote_ip"
		openvpn_down="vpnchain_helper.sh -d $next_client_remote_ip"
	}

	# We need to get available tun device (that is not currently in use). Yes, openvpn can detect this automaticaly,
	# but in our case we need to assign them manualy, because we need to put them in array for function that checks
	# if the chain is connected.
	client_tun=$(get_tun)

	# Block all outgoing traffic except OpenVPN servers
	[[ $killswitch -gt 0 && $i -eq 0 ]] && {
        entry_vpn_ip=$client_remote_ip
        iptables -I OUTPUT -d $entry_vpn_ip -j ACCEPT
    } || unset entry_vpn_ip

	# Start vpn connection
	openvpn --config ${config[$i]} --remote $client_remote_ip --dev $client_tun --verb $verbose --script-security 2 --remote-cert-tls server --auth-nocache --route-nopull $openvpn_options --up "$openvpn_up" --down "$openvpn_down" &
	openvpnpid=$!

	log info "Connecting to VPN #$((i+1)) of $((chain_length+1)): ${config[$i]} ($client_remote_ip) on $client_tun"

	waits=0

	# Wait for VPN to connect
	while sleep 5; do
		[ -d "/sys/class/net/$client_tun" ] && {
			# Add to array for checking if the chain is connected in the future
			tun_array+=("$client_tun")

			# If all connections done, then we jump to chains connection checking function
			[ $i -eq $chain_length ] && while_connected || (( i++ ))
			# Otherwise switch to the next VPN in the chain to connect

			break
		}

		log info "Waiting for $client_tun..."
		(( waits++ ))

		# If OpenVPN subprocess is no longer running or has been for (15 + chains * 10) seconds, kill it and try another 
		[[ ! -d "/proc/$openvpnpid" || $waits -ge $((3+(i*2))) ]] && {
			kill $openvpnpid 2> /dev/null

			log error "Couldn't connect to $client_remote_ip"

			# Remove rule for the non-working VPN
			[[ $killswitch -gt 0 && $i = 0 ]] && iptables -D OUTPUT -d $entry_vpn_ip -j ACCEPT 

            [ $replace_broken -gt 0 ] || break 2

			for vpn in $(get_configs | paste -sd ' '); do
				echo ${config[@]} | grep -qw "$vpn" && continue # Skip if already used
				config[$i]="$vpn"
				new_client_remote_ip=$(get_ip "$vpn")

				# Allow connection to replacement VPN if it's the first
				[[ $killswitch -gt 0 && $i = 0 ]] && iptables -I OUTPUT -d $new_client_remote_ip -j ACCEPT

				# Replace route (messy)
				[ $i -gt 0 ] && {
					mygod=$(ip route show $client_remote_ip | awk '{ for(i=1;i<NF;i++) { if ($i == "via") { print $++i; exit } } }')
					ip route delete $client_remote_ip
					ip route add $new_client_remote_ip via $mygod scope link
				}

				break 2
			done

            [ ! -v $new_client_remote_ip ] && {
                log error "Couldn't find replacement."
                break 2
            }
		}
	done
done

on_exit
