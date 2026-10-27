#!/usr/bin/env bash
# VeyraScope — local system and authorized nearby-device explorer for Linux Mint.
# Device discovery is limited to the current local subnet; deeper fingerprinting is opt-in.
set -u

APP_NAME="VeyraScope"
DOWNLOADS="${HOME}/Downloads"
PREVIOUS_HOSTS_FILE="${DOWNLOADS}/veyrascope-previous-hosts.txt"
CSV_FILE="${DOWNLOADS}/veyrascope-inventory.csv"
NOTES_FILE="${DOWNLOADS}/veyrascope-device-notes.txt"
REPORT_FILE="${DOWNLOADS}/veyrascope-report.txt"
DISCOVERY_FILE="${DOWNLOADS}/veyrascope-devices.txt"
HOSTS_FILE="${DOWNLOADS}/veyrascope-hosts.txt"
FINGERPRINT_FILE="${DOWNLOADS}/veyrascope-fingerprints.txt"
MDNS_FILE="${DOWNLOADS}/veyrascope-mdns.txt"
UPNP_FILE="${DOWNLOADS}/veyrascope-upnp-models.txt"
BT_FILE="${DOWNLOADS}/veyrascope-bluetooth.txt"

cyan=$'\033[1;36m'; green=$'\033[1;32m'; yellow=$'\033[1;33m'; red=$'\033[1;31m'; reset=$'\033[0m'

have_cmd() { command -v "$1" >/dev/null 2>&1; }

pause() { printf '\nPress Enter to return to the menu...'; IFS= read -r _ || true; }

header() {
  clear 2>/dev/null || true
  printf '%s' "$cyan"
  cat <<'BANNER'
 __      __                  _____                      
 \ \    / /__ _   _ _ __ __ _/ ____|___ ___  _ __   ___ 
  \ \/\/ / _ \ | | | '__/ _` | |   / __/ _ \| '_ \ / _ \
   \  /\/  __/ |_| | | | (_| | |__| (_| (_) | |_) |  __/
    \/  \___|\__,_|_|  \__,_|\_____\___\___/| .__/ \___|
                                               |_|
BANNER
  printf '%s\n' "$reset"
  printf '  VeyraScope v3.1 — enhanced local network inventory and device management\n'
  printf '%s\n\n' '----------------------------------------------------------------'
}

need_downloads() { mkdir -p "$DOWNLOADS" 2>/dev/null || true; }

local_system() {
  header
  printf '%s\n\n' '=== THIS COMPUTER ==='
  if have_cmd hostnamectl; then hostnamectl; else uname -a; fi
  printf '\n%s\n' '=== OPERATING SYSTEM ==='
  if [[ -r /etc/os-release ]]; then . /etc/os-release; printf '%s\n' "${PRETTY_NAME:-Linux}"; fi
  printf '\n%s\n' '=== KERNEL ==='; uname -srmo
  printf '\n%s\n' '=== CPU ==='
  if have_cmd lscpu; then lscpu | grep -E '^(Architecture|CPU\(s\)|Model name|Thread|Core|Socket|Virtualization):' || lscpu; else grep -m1 'model name' /proc/cpuinfo 2>/dev/null || true; fi
  printf '\n%s\n' '=== MEMORY ==='; if have_cmd free; then free -h; else cat /proc/meminfo | head; fi
  printf '\n%s\n' '=== STORAGE ==='; if have_cmd lsblk; then lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS 2>/dev/null || lsblk; else df -h; fi
  printf '\n%s\n' '=== NETWORK INTERFACES ==='; if have_cmd ip; then ip -brief address; else echo 'ip command not installed.'; fi
  pause
}

network_info() {
  header
  printf '%s\n\n' '=== IP ADDRESSES ==='; if have_cmd ip; then ip -brief address; else echo 'ip command not installed.'; fi
  printf '\n%s\n' '=== ROUTES ==='; if have_cmd ip; then ip route; else echo 'Unavailable.'; fi
  printf '\n%s\n' '=== NEIGHBOR CACHE (devices recently seen by this PC) ==='; if have_cmd ip; then ip neigh show; else echo 'Unavailable.'; fi
  printf '\n%s\n' '=== mDNS / BONJOUR DISCOVERY ==='
  if have_cmd avahi-browse; then
    timeout 8s avahi-browse -art 2>/dev/null | grep -E '^[+=];' | head -n 35 || true
    echo 'mDNS names can reveal device names and advertised services, not always exact models.'
  else
    echo 'Optional: install avahi-utils to list devices/services advertised on the local network.'
  fi
  pause
}

# Convert an IPv4 address to an unsigned integer (valid only for checked IPv4 input).
ip_to_int() {
  local a b c d
  IFS=. read -r a b c d <<< "$1"
  echo $(( (a << 24) | (b << 16) | (c << 8) | d ))
}
int_to_ip() {
  local n=$1
  printf '%d.%d.%d.%d' "$(( (n >> 24) & 255 ))" "$(( (n >> 16) & 255 ))" "$(( (n >> 8) & 255 ))" "$(( n & 255 ))"
}

# Detect the active route/interface. Keep large LANs narrowed to a /24 by default.
detect_local_network() {
  local iface addr prefix effective ipnum mask network_num network_ip
  iface="$(ip -4 route show default 2>/dev/null | awk 'NR==1 {print $5}')"
  if [[ -z "$iface" ]]; then iface="$(ip -o -4 addr show scope global 2>/dev/null | awk 'NR==1 {print $2}')"; fi
  [[ -n "$iface" ]] || return 1
  read -r addr prefix < <(ip -o -4 addr show dev "$iface" scope global 2>/dev/null | awk 'NR==1 {split($4,a,"/"); print a[1],a[2]}')
  [[ -n "${addr:-}" && -n "${prefix:-}" ]] || return 1
  effective=$prefix
  if (( effective < 24 || effective > 30 )); then effective=24; fi
  ipnum=$(ip_to_int "$addr")
  mask=$(( (0xffffffff << (32 - effective)) & 0xffffffff ))
  network_num=$(( ipnum & mask ))
  network_ip=$(int_to_ip "$network_num")
  printf '%s %s/%s %s/%s\n' "$iface" "$network_ip" "$effective" "$addr" "$prefix"
}

valid_ipv4() {
  local value=$1 part
  local -a octets
  [[ "$value" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  IFS='.' read -r -a octets <<< "$value"
  [[ ${#octets[@]} -eq 4 ]] || return 1
  for part in "${octets[@]}"; do (( 10#$part >= 0 && 10#$part <= 255 )) || return 1; done
}

extract_arp_hosts() {
  awk '
    $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {
      n = split($2, mac, ":")
      if (n == 6) {
        good = 1
        for (i = 1; i <= 6; i++) {
          if (length(mac[i]) != 2 || mac[i] !~ /^[[:xdigit:]][[:xdigit:]]$/) good = 0
        }
        if (good) print $1
      }
    }
  ' "$1" | sort -Vu
}

extract_nmap_hosts() {
  awk '/Status: Up$/{print $2}' "$1" | sort -Vu
}

# Query UPnP device-description XML only from IP addresses already discovered
# on the local LAN. This can reveal friendlyName/manufacturer/modelName/modelNumber.
upnp_model_discovery() {
  local iface="$1" ssdp_tmp url device_ip xml friendly manufacturer model modelnum dtype
  : > "$UPNP_FILE"
  if ! have_cmd gssdp-discover; then
    echo 'Optional exact-model hint: install gupnp-tools (provides gssdp-discover).'
    return
  fi
  if ! have_cmd curl; then
    echo 'UPnP model lookup needs curl. Install: sudo apt install curl'
    return
  fi
  ssdp_tmp=$(mktemp) || return
  echo 'Searching for UPnP/SSDP devices (TVs, media boxes, routers and some printers)...'
  gssdp-discover --interface="$iface" --timeout=5 > "$ssdp_tmp" 2>&1 || true
  while IFS= read -r url; do
    # Only follow plain-HTTP URLs with a literal IPv4 address already discovered.
    # This avoids following redirects or device-advertised external hostnames.
    [[ "$url" =~ ^http://(([0-9]{1,3}\.){3}[0-9]{1,3})(:[0-9]{1,5})?/[^[:space:]]*$ ]] || continue
    device_ip="${BASH_REMATCH[1]}"
    grep -Fxq -- "$device_ip" "$HOSTS_FILE" || continue
    xml=$(curl --noproxy '*' --connect-timeout 2 --max-time 3 --max-filesize 200000 -fsS -- "$url" 2>/dev/null) || continue
    if have_cmd xmllint; then
      friendly=$(printf '%s' "$xml" | xmllint --xpath 'string((//*[local-name()="friendlyName"])[1])' - 2>/dev/null | head -c 160)
      manufacturer=$(printf '%s' "$xml" | xmllint --xpath 'string((//*[local-name()="manufacturer"])[1])' - 2>/dev/null | head -c 160)
      model=$(printf '%s' "$xml" | xmllint --xpath 'string((//*[local-name()="modelName"])[1])' - 2>/dev/null | head -c 160)
      modelnum=$(printf '%s' "$xml" | xmllint --xpath 'string((//*[local-name()="modelNumber"])[1])' - 2>/dev/null | head -c 160)
      dtype=$(printf '%s' "$xml" | xmllint --xpath 'string((//*[local-name()="deviceType"])[1])' - 2>/dev/null | head -c 180)
    else
      local flat
      flat=$(printf '%s' "$xml" | tr '\r\n' ' ')
      friendly=$(printf '%s' "$flat" | sed -nE 's#.*<friendlyName[^>]*>([^<]*)</friendlyName>.*#\1#p' | head -c 160)
      manufacturer=$(printf '%s' "$flat" | sed -nE 's#.*<manufacturer[^>]*>([^<]*)</manufacturer>.*#\1#p' | head -c 160)
      model=$(printf '%s' "$flat" | sed -nE 's#.*<modelName[^>]*>([^<]*)</modelName>.*#\1#p' | head -c 160)
      modelnum=$(printf '%s' "$flat" | sed -nE 's#.*<modelNumber[^>]*>([^<]*)</modelNumber>.*#\1#p' | head -c 160)
      dtype=$(printf '%s' "$flat" | sed -nE 's#.*<deviceType[^>]*>([^<]*)</deviceType>.*#\1#p' | head -c 180)
    fi
    if [[ -n "$friendly$manufacturer$model$modelnum$dtype" ]]; then
      {
        printf 'IP: %s\n' "$device_ip"
        [[ -n "$friendly" ]] && printf '  Name: %s\n' "$friendly"
        [[ -n "$manufacturer" ]] && printf '  Manufacturer: %s\n' "$manufacturer"
        [[ -n "$model" ]] && printf '  Model: %s\n' "$model"
        [[ -n "$modelnum" ]] && printf '  Model number: %s\n' "$modelnum"
        [[ -n "$dtype" ]] && printf '  Device type: %s\n' "$dtype"
        printf '  Source: UPnP device description\n\n'
      } | tee -a "$UPNP_FILE"
    fi
  done < <(sed -nE 's/^[[:space:]]*Location:[[:space:]]*(http:\/\/[^[:space:]]+).*$/\1/p' "$ssdp_tmp" | sort -u)
  rm -f "$ssdp_tmp"
  if [[ ! -s "$UPNP_FILE" ]]; then
    echo 'No UPnP model details returned. The device may not support UPnP or may hide its model.'
  else
    echo "UPnP identity details saved to: $UPNP_FILE"
  fi
}

nearby_devices() {
  header
  printf '%s\n' '=== NEARBY DEVICES ON YOUR CURRENT LOCAL NETWORK ==='
  printf '%s\n' 'This scans only the current LAN. Device names/vendors/models are shown only when the network exposes them.'
  if ! have_cmd ip; then echo 'The iproute2 tools are missing. Install: sudo apt install iproute2'; pause; return; fi
  local detected iface cidr local_addr temp rc
  detected="$(detect_local_network 2>/dev/null)" || {
    echo 'Could not automatically detect a local IPv4 network.'
    echo 'Connect to Wi-Fi/Ethernet first, then try again.'; pause; return;
  }
  read -r iface cidr local_addr <<< "$detected"
  printf '\nInterface: %s\nLocal address: %s\nDiscovery range: %s\n' "$iface" "$local_addr" "$cidr"
  if [[ "$local_addr" != */24 && "$cidr" == */24 ]]; then
    echo 'Note: the interface uses a larger/special subnet; discovery is limited to a /24 around this computer.'
  fi
  need_downloads
  if [[ -s "$HOSTS_FILE" ]]; then cp -f -- "$HOSTS_FILE" "$PREVIOUS_HOSTS_FILE" 2>/dev/null || true; fi
  : > "$HOSTS_FILE"
  : > "$DISCOVERY_FILE"
  : > "$MDNS_FILE"
  : > "$UPNP_FILE"
  temp=$(mktemp) || { echo 'Could not create temporary file.'; pause; return; }
  printf '\n%s\n' 'Starting local discovery...'
  if have_cmd arp-scan; then
    echo 'Method: ARP discovery (usually best for devices on the same Wi-Fi/LAN).'
    if (( EUID == 0 )); then
      arp-scan --interface="$iface" "$cidr" 2>&1 | tee "$temp"
      rc=${PIPESTATUS[0]}
    elif have_cmd sudo; then
      sudo arp-scan --interface="$iface" "$cidr" 2>&1 | tee "$temp"
      rc=${PIPESTATUS[0]}
    else
      rc=1
    fi
    if (( rc == 0 )); then
      extract_arp_hosts "$temp" > "$HOSTS_FILE"
      cp "$temp" "$DISCOVERY_FILE"
    else
      echo 'ARP discovery did not complete; falling back to Nmap host discovery.'
    fi
  fi
  if [[ ! -s "$HOSTS_FILE" ]]; then
    if ! have_cmd nmap; then
      echo 'Neither arp-scan nor nmap is installed.'
      echo 'Install recommended tools with: sudo apt update && sudo apt install nmap arp-scan avahi-utils bluez gupnp-tools curl libxml2-utils'
      rm -f "$temp"; pause; return
    fi
    nmap -sn -n -oG "$temp" -- "$cidr"
    extract_nmap_hosts "$temp" > "$HOSTS_FILE"
    cp "$temp" "$DISCOVERY_FILE"
  fi
  rm -f "$temp"
  printf '\n%s\n' '=== DISCOVERED HOSTS ==='
  if [[ -s "$HOSTS_FILE" ]]; then
    if grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[[:space:]]' "$DISCOVERY_FILE"; then
      # Show raw arp-scan IP / MAC / vendor rows if available.
      awk '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && $2 ~ /^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$/ {print}' "$DISCOVERY_FILE"
    else
      sed 's/^/Active host: /' "$HOSTS_FILE"
    fi
    printf '\nFound %s host(s). IP list saved to: %s\n' "$(wc -l < "$HOSTS_FILE" | tr -d ' ')" "$HOSTS_FILE"
  else
    echo 'No responding devices were found. Some devices may block discovery or isolate Wi-Fi clients.'
  fi
  printf '\n%s\n' '=== mDNS / BONJOUR DEVICE NAMES AND SERVICES ==='
  if have_cmd avahi-browse; then
    timeout 10s avahi-browse -art 2>/dev/null | grep -E '^[+=];' | tee "$MDNS_FILE" | head -n 40 || true
    echo 'mDNS results may expose device names, printers, media devices and service types.'
  else
    echo 'Optional extra: sudo apt install avahi-utils'
  fi
  printf '\n%s\n' '=== UPnP MODEL DETAILS (WHEN DEVICES PUBLISH THEM) ==='
  upnp_model_discovery "$iface"
  printf '\n%s\n' 'What device identity means:'
  echo '• MAC vendor (if shown) identifies the network-card maker, not necessarily the whole device.'
  echo '• Hostnames / Bonjour advertisements may contain a model or device name.'
  echo '• Exact model numbers are often not publicly exposed; use the deeper scan only on your own/authorized LAN.'
  pause
}

bluetooth_discovery() {
  header
  echo '=== NEARBY BLUETOOTH DEVICES ==='
  if ! have_cmd bluetoothctl; then
    echo 'Bluetooth tools are not installed. Optional: sudo apt install bluez'
    pause; return
  fi
  echo 'This briefly searches for discoverable Bluetooth devices nearby.'
  echo 'Some phones/headphones stay invisible unless pairing/discovery mode is enabled.'
  printf 'Start a 12-second Bluetooth scan? [y/N] '
  local confirm
  IFS= read -r confirm || confirm='n'
  [[ "$confirm" =~ ^[Yy]$ ]] || return
  need_downloads
  echo 'Scanning for 12 seconds...'
  {
    printf 'power on\n'
    sleep 1
    printf 'scan on\n'
    sleep 12
    printf 'scan off\n'
    printf 'devices\n'
    sleep 1
  } | bluetoothctl 2>&1 | tee "$BT_FILE"
  echo
  echo 'The displayed name is provided by the device and may not be its exact model.'
  echo "Results saved to: $BT_FILE"
  pause
}

fingerprint_devices() {
  header
  echo '=== OPTIONAL DEVICE OS / SERVICE FINGERPRINT ==='
  echo 'This sends additional probes to devices found in the last local discovery.'
  echo 'Only continue on devices/networks you own or are explicitly authorized to inspect.'
  if ! have_cmd nmap; then
    echo 'Nmap is required. Install: sudo apt install nmap'; pause; return
  fi
  if [[ ! -s "$HOSTS_FILE" ]]; then
    echo 'No saved device list found. Run menu option 3 first.'; pause; return
  fi
  local -a targets=()
  local ip
  while IFS= read -r ip; do
    valid_ipv4 "$ip" && targets+=("$ip")
  done < "$HOSTS_FILE"
  if (( ${#targets[@]} == 0 )); then echo 'No valid hosts in the saved list.'; pause; return; fi
  printf 'Found %d host(s). Check OS clues and selected common service ports? [y/N] ' "${#targets[@]}"
  local confirm
  IFS= read -r confirm || confirm='n'
  [[ "$confirm" =~ ^[Yy]$ ]] || return
  need_downloads
  echo
  echo 'Scanning selected common ports with light version detection; this is not a full-port scan.'
  echo 'A model may still be impossible to infer if the device hides its identity.'
  local -a nmap_args=( -sV --version-light -O --osscan-guess --script=http-title -T2 --max-retries 2 -p '22,23,53,80,81,139,443,445,515,554,631,8008,8009,8080,8443,8554,9100,5000,5001,32400' -oN "$FINGERPRINT_FILE" )
  if (( EUID == 0 )); then
    nmap "${nmap_args[@]}" "${targets[@]}"
  elif have_cmd sudo; then
    sudo nmap "${nmap_args[@]}" "${targets[@]}"
  else
    nmap "${nmap_args[@]}" "${targets[@]}"
  fi
  printf '\nReport saved to: %s\n' "$FINGERPRINT_FILE"
  echo 'Look for OS guesses, device type, service product/version, HTTP titles and printer/media services.'
  pause
}

device_details() {
  header
  echo '=== DEVICE DETAIL EXPLORER ==='
  if [[ ! -s "$HOSTS_FILE" ]]; then
    echo 'No saved device list yet. Run option 3 (LAN discovery) first.'
    pause; return
  fi

  echo 'Devices from the most recent LAN discovery:'
  local idx=0 ip host mac macvendor
  printf '  %-4s %-15s %-24s %-18s %s\n' '#' 'IP address' 'Hostname' 'MAC address' 'MAC vendor'
  while IFS= read -r ip; do
    valid_ipv4 "$ip" || continue
    ((idx+=1))
    host="$(getent hosts "$ip" 2>/dev/null | awk 'NR==1 {print $2}')"
    mac="$(mac_for_ip "$ip")"
    macvendor="$(vendor_for_ip "$ip")"
    [[ -n "$host" ]] || host='unknown'
    [[ -n "$mac" ]] || mac='unavailable'
    [[ -n "$macvendor" ]] || macvendor='unknown'
    printf '  [%-2d] %-15s %-24.24s %-18s %s\n' "$idx" "$ip" "$host" "$mac" "$macvendor"
  done < "$HOSTS_FILE"

  echo
  printf 'Enter an IP address from this list (or q to return): '
  local chosen
  IFS= read -r chosen || return
  [[ "$chosen" == 'q' || "$chosen" == 'Q' ]] && return
  if ! valid_ipv4 "$chosen" || ! grep -Fxq -- "$chosen" "$HOSTS_FILE"; then
    echo 'That address is not in the most recent discovered-host list.'
    pause; return
  fi

  header
  printf '=== DETAILS FOR %s ===\n\n' "$chosen"
  printf '%s\n' '--- Hostname / DNS ---'
  getent hosts "$chosen" 2>/dev/null || echo 'No reverse DNS name returned.'

  printf '\n%s\n' '--- MAC address and vendor (if ARP scan provided them) ---'
  if [[ -s "$DISCOVERY_FILE" ]] && awk -v target="$chosen" '$1 == target && $2 ~ /:/ {found=1} END {exit !found}' "$DISCOVERY_FILE"; then
    awk -v target="$chosen" '$1 == target && $2 ~ /:/ {print; found=1} END {if (!found) print "Not available in saved scan."}' "$DISCOVERY_FILE"
  else
    echo 'Not available in the saved scan.'
  fi

  printf '\n%s\n' '--- UPnP model information ---'
  if [[ -s "$UPNP_FILE" ]]; then
    awk -v target="$chosen" 'BEGIN {RS=""; found=0} index($0, "IP: " target "\n") == 1 {print; found=1} END {if (!found) print "No UPnP model details were published for this device."}' "$UPNP_FILE"
  else
    echo 'No UPnP model lookup has been saved yet; run option 3.'
  fi

  printf '\n%s\n' '--- Saved notes for this device ---'
  if [[ -s "$NOTES_FILE" ]]; then
    awk -F '\t' -v target="$chosen" '$2 == target {print; found=1} END {if (!found) print "No saved note for this IP."}' "$NOTES_FILE"
  else echo 'No notes saved.'; fi

  printf '\n%s\n' '--- OS and service fingerprint ---'
  if [[ -s "$FINGERPRINT_FILE" ]]; then
    awk -v target="$chosen" '$0 ~ "Nmap scan report for " target "([[:space:]]|$)" {show=1} show {print} show && /^$/ {show=0}' "$FINGERPRINT_FILE"
  else
    echo 'No deeper scan saved yet; run option 5 on an authorized network.'
  fi
  echo
  echo 'Accuracy note: MAC vendor is the adapter maker, not always device brand.'
  echo 'Exact model and operating system can remain unknown if a device hides them.'
  pause
}

wake_by_mac() {
  header
  echo '=== WAKE-ON-LAN BY KNOWN MAC ADDRESS ==='
  echo 'Use a MAC address for a device you own or administer.'
  echo 'The target usually must have Wake-on-LAN enabled in firmware and its network adapter.'
  if ! have_cmd wakeonlan && ! have_cmd etherwake; then
    echo 'No Wake-on-LAN sender installed. Install: sudo apt install wakeonlan'
    pause; return
  fi
  local mac iface confirm
  printf '\nMAC address (example 00:11:22:33:44:55, or q to cancel) > '
  IFS= read -r mac || return
  [[ "$mac" =~ ^[Qq]$ ]] && return
  mac="${mac,,}"
  if [[ ! "$mac" =~ ^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$ ]]; then
    echo 'Invalid MAC address format.'; pause; return
  fi
  echo
  echo "Ready to send a Wake-on-LAN packet to $mac."
  echo 'This sends a standard magic packet; it does not bypass login or device security.'
  printf 'Type WAKE to send, or anything else to cancel > '
  IFS= read -r confirm || confirm=''
  if [[ "$confirm" != 'WAKE' ]]; then echo 'Cancelled.'; pause; return; fi
  if have_cmd wakeonlan; then
    wakeonlan "$mac"
  else
    iface="$(ip -4 route show default 2>/dev/null | awk 'NR==1 {print $5}')"
    if [[ -z "$iface" ]]; then
      echo 'Could not determine the active network interface.'
    elif (( EUID == 0 )); then
      etherwake -i "$iface" "$mac"
    elif have_cmd sudo; then
      sudo etherwake -i "$iface" "$mac"
    else
      echo 'etherwake may require root privileges; run it with sudo.'
    fi
  fi
  echo
  echo 'If it does not wake, check BIOS/UEFI WoL, operating-system power settings, wired Ethernet and router broadcast rules.'
  pause
}

check_tools() {
  header
  echo '=== OPTIONAL COMPONENT STATUS ==='
  local cmd pkg
  for cmd in ip nmap arp-scan avahi-browse bluetoothctl gssdp-discover curl xmllint ss ssh remmina wakeonlan; do
    if have_cmd "$cmd"; then
      printf '  [OK]      %s\n' "$cmd"
    else
      printf '  [missing] %s\n' "$cmd"
    fi
  done
  echo
  echo 'Install all recommended helpers on Linux Mint with:'
  echo 'sudo apt update && sudo apt install -y nmap arp-scan avahi-utils bluez gupnp-tools curl libxml2-utils iproute2 openssh-client wakeonlan remmina'
  echo 'VeyraScope itself is a standalone Bash script; optional tools improve discovery.'
  pause
}

compare_scans() {
  header
  echo '=== COMPARE THE TWO MOST RECENT LAN DISCOVERIES ==='
  if [[ ! -s "$HOSTS_FILE" ]]; then
    echo 'No current device list found. Run option 3 first.'
    pause; return
  fi
  if [[ ! -s "$PREVIOUS_HOSTS_FILE" ]]; then
    echo 'There is no previous scan yet.'
    echo 'Run option 3 now, then run it again later to compare changes.'
    pause; return
  fi
  local new_count gone_count
  echo
  echo 'Newly seen since the previous scan:'
  new_count=0
  while IFS= read -r ip; do
    [[ -n "$ip" ]] || continue
    if ! grep -Fxq -- "$ip" "$PREVIOUS_HOSTS_FILE"; then
      printf '  + %s  %s\n' "$ip" "$(getent hosts "$ip" 2>/dev/null | awk 'NR==1 {print $2}')"
      ((new_count+=1))
    fi
  done < "$HOSTS_FILE"
  (( new_count > 0 )) || echo '  None detected.'
  echo
  echo 'Not seen in the latest scan (may be offline or blocking discovery):'
  gone_count=0
  while IFS= read -r ip; do
    [[ -n "$ip" ]] || continue
    if ! grep -Fxq -- "$ip" "$HOSTS_FILE"; then
      printf '  - %s\n' "$ip"
      ((gone_count+=1))
    fi
  done < "$PREVIOUS_HOSTS_FILE"
  (( gone_count > 0 )) || echo '  None detected.'
  echo
  printf 'Current: %s host(s) | Previous: %s host(s)\n' "$(wc -l < "$HOSTS_FILE" | tr -d ' ')" "$(wc -l < "$PREVIOUS_HOSTS_FILE" | tr -d ' ')"
  echo 'Discovery can miss sleeping devices or clients isolated by the Wi-Fi access point.'
  pause
}

csv_quote() {
  local value=${1//\"/\"\"}
  printf '"%s"' "$value"
}

mac_for_ip() {
  local target="$1" line
  local -a fields=()
  [[ -r "$DISCOVERY_FILE" ]] || return 0
  while IFS= read -r line; do
    read -r -a fields <<< "$line"
    if [[ "${fields[0]:-}" == "$target" && "${fields[1]:-}" == *:* ]]; then
      if [[ "${fields[1]}" =~ ^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$ ]]; then
        printf '%s\n' "${fields[1],,}"
        return 0
      fi
    fi
  done < "$DISCOVERY_FILE"
}

vendor_for_ip() {
  local target="$1" line
  local -a fields=()
  [[ -r "$DISCOVERY_FILE" ]] || return 0
  while IFS= read -r line; do
    read -r -a fields <<< "$line"
    if [[ "${fields[0]:-}" == "$target" && "${fields[1]:-}" =~ ^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$ ]]; then
      if (( ${#fields[@]} > 2 )); then
        printf '%s' "${fields[*]:2}"
      fi
      return 0
    fi
  done < "$DISCOVERY_FILE"
}

export_inventory_csv() {
  header
  need_downloads
  if [[ ! -s "$HOSTS_FILE" ]]; then
    echo 'No saved device list. Run option 3 first.'
    pause; return
  fi
  local tmp ip name mac vendor
  tmp=$(mktemp "${DOWNLOADS}/.veyrascope-inventory.XXXXXX") || { echo 'Could not create temporary file.'; pause; return; }
  printf 'ip,hostname,mac_address,mac_vendor,identity_source\n' > "$tmp"
  while IFS= read -r ip; do
    valid_ipv4 "$ip" || continue
    name="$(getent hosts "$ip" 2>/dev/null | awk 'NR==1 {print $2}')"
    mac="$(mac_for_ip "$ip")"
    vendor="$(vendor_for_ip "$ip")"
    local source='LAN discovery'
    if [[ -s "$UPNP_FILE" ]] && grep -Fq "IP: $ip" "$UPNP_FILE"; then source='UPnP + LAN discovery'; fi
    csv_quote "$ip" >> "$tmp"; printf ',' >> "$tmp"
    csv_quote "$name" >> "$tmp"; printf ',' >> "$tmp"
    csv_quote "$mac" >> "$tmp"; printf ',' >> "$tmp"
    csv_quote "$vendor" >> "$tmp"; printf ',' >> "$tmp"
    csv_quote "$source" >> "$tmp"; printf '\n' >> "$tmp"
  done < "$HOSTS_FILE"
  if mv -f -- "$tmp" "$CSV_FILE"; then
    echo 'CSV inventory exported successfully.'
    echo "File: $CSV_FILE"
    echo 'Open it with LibreOffice Calc or another spreadsheet application.'
  else
    rm -f -- "$tmp"
    echo 'Could not save the inventory.'
  fi
  pause
}

monitor_device() {
  header
  echo '=== SHORT REACHABILITY MONITOR ==='
  if ! have_cmd ping; then echo 'ping is not installed.'; pause; return; fi
  if ! select_discovered_device; then pause; return; fi
  local target="$SELECTED_IP" count=0 success=0 result logfile
  logfile="${DOWNLOADS}/veyrascope-monitor-${target}.txt"
  need_downloads
  echo
  echo "Monitoring $target for about 30 seconds (checks approximately every 2 seconds)."
  echo "A log will be saved to: $logfile"
  printf 'Timestamp\tTarget\tResult\n' >> "$logfile"
  while (( count < 15 )); do
    if ping -c 1 -W 1 "$target" >/dev/null 2>&1; then result='ONLINE'; ((success+=1)); else result='NO PING REPLY'; fi
    printf '%s  %-15s %s (%d/%d)\n' "$(date '+%H:%M:%S')" "$target" "$result" "$((count+1))" 15
    printf '%s\t%s\t%s\n' "$(date '+%F %T')" "$target" "$result" >> "$logfile"
    ((count+=1))
    (( count < 15 )) && sleep 1
  done
  echo
  printf 'Replies: %d/15. Note: lack of ping reply does not always mean the device is offline.\n' "$success"
  pause
}

local_services() {
  header
  printf '%s\n\n' '=== SERVICES LISTENING ON THIS COMPUTER ==='
  if have_cmd ss; then ss -lntup 2>&1 || ss -lntu; else echo 'The ss command is unavailable. Install iproute2.'; fi
  printf '\nNote: process names may require elevated permissions to display.\n'
  pause
}

save_report() {
  header
  need_downloads
  local tmp
  tmp=$(mktemp 2>/dev/null) || { echo 'Could not create a temporary report.'; pause; return; }
  {
    echo 'VEYRASCOPE REPORT'
    echo "Generated: $(date)"
    echo
    echo '=== SYSTEM ==='; if have_cmd hostnamectl; then hostnamectl; else uname -a; fi
    echo; echo '=== OS ==='; cat /etc/os-release 2>/dev/null || true
    echo; echo '=== KERNEL ==='; uname -a
    echo; echo '=== CPU ==='; (have_cmd lscpu && lscpu) 2>/dev/null || grep -m1 'model name' /proc/cpuinfo 2>/dev/null || true
    echo; echo '=== MEMORY ==='; (have_cmd free && free -h) 2>/dev/null || cat /proc/meminfo
    echo; echo '=== STORAGE ==='; (have_cmd lsblk && lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS) 2>/dev/null || df -h
    echo; echo '=== NETWORK INTERFACES ==='; (have_cmd ip && ip -brief address) 2>/dev/null || true
    echo; echo '=== ROUTES ==='; (have_cmd ip && ip route) 2>/dev/null || true
    echo; echo '=== NEIGHBORS ==='; (have_cmd ip && ip neigh show) 2>/dev/null || true
    echo; echo '=== LISTENING SOCKETS ==='; (have_cmd ss && ss -lntup) 2>/dev/null || true
    if [[ -f "$DISCOVERY_FILE" ]]; then echo; echo '=== LAST DEVICE DISCOVERY ==='; cat "$DISCOVERY_FILE"; fi
    if [[ -f "$MDNS_FILE" ]]; then echo; echo '=== LAST mDNS DISCOVERY ==='; cat "$MDNS_FILE"; fi
    if [[ -f "$UPNP_FILE" ]]; then echo; echo '=== LAST UPnP MODEL DETAILS ==='; cat "$UPNP_FILE"; fi
    if [[ -f "$BT_FILE" ]]; then echo; echo '=== LAST BLUETOOTH DISCOVERY ==='; cat "$BT_FILE"; fi
    if [[ -f "$FINGERPRINT_FILE" ]]; then echo; echo '=== LAST DEVICE FINGERPRINT ==='; cat "$FINGERPRINT_FILE"; fi
    if [[ -f "$PREVIOUS_HOSTS_FILE" ]]; then echo; echo '=== PREVIOUS DEVICE IP LIST ==='; cat "$PREVIOUS_HOSTS_FILE"; fi
    if [[ -f "$CSV_FILE" ]]; then echo; echo '=== EXPORTED CSV INVENTORY ==='; cat "$CSV_FILE"; fi
    if [[ -f "$NOTES_FILE" ]]; then echo; echo '=== DEVICE NOTES ==='; cat "$NOTES_FILE"; fi
  } > "$tmp"
  if mv "$tmp" "$REPORT_FILE"; then printf '%s\n' "${green}Report saved to:${reset} $REPORT_FILE"; else rm -f "$tmp"; echo 'Could not save report.'; fi
  pause
}


# Select one host from the most recent, explicitly performed LAN discovery.
# The selected target is always taken from HOSTS_FILE, never from arbitrary input.
SELECTED_IP=""
select_discovered_device() {
  local ip idx=0 selection
  local -a ips=()
  if [[ ! -s "$HOSTS_FILE" ]]; then
    echo 'No saved device list. Run option 3 first.'
    return 1
  fi
  while IFS= read -r ip; do
    valid_ipv4 "$ip" && ips+=("$ip")
  done < "$HOSTS_FILE"
  if (( ${#ips[@]} == 0 )); then
    echo 'No valid devices are listed in the last scan.'
    return 1
  fi
  echo 'Choose a device from the last LAN discovery:'
  printf '  %-4s %-15s %-24s %-18s %s\n' '#' 'IP address' 'Hostname' 'MAC address' 'MAC vendor'
  for ip in "${ips[@]}"; do
    ((idx+=1))
    local name mac vendor
    name="$(getent hosts "$ip" 2>/dev/null | awk 'NR==1 {print $2}')"
    mac="$(mac_for_ip "$ip")"
    vendor="$(vendor_for_ip "$ip")"
    [[ -n "$name" ]] || name='unknown'
    [[ -n "$mac" ]] || mac='unavailable'
    [[ -n "$vendor" ]] || vendor='unknown'
    printf '  [%-2d] %-15s %-24.24s %-18s %s\n' "$idx" "$ip" "$name" "$mac" "$vendor"
  done
  printf '\nNumber (or q to cancel) > '
  IFS= read -r selection || return 1
  [[ "$selection" =~ ^[Qq]$ ]] && return 1
  [[ "$selection" =~ ^[0-9]+$ ]] || { echo 'Enter a device number.'; return 1; }
  # Force decimal parsing so input such as 08 is not treated as octal.
  idx=$((10#$selection))
  (( idx >= 1 && idx <= ${#ips[@]} )) || { echo 'Number out of range.'; return 1; }
  SELECTED_IP="${ips[idx-1]}"
}

control_device() {
  header
  echo '=== DEVICE MANAGEMENT ==='
  echo 'Use only devices you own or are authorized to administer.'
  echo 'Available actions use normal network protocols and your existing credentials.'
  echo
  if ! select_discovered_device; then pause; return; fi
  local target="$SELECTED_IP" action url port mac iface confirm username
  while true; do
    header
    printf 'Selected device: %s\n\n' "$target"
    echo ' [1] Check whether the device responds (ping)'
    echo ' [2] Open its web interface in the browser'
    echo ' [3] Connect by SSH using my normal account/keys'
    echo ' [4] Wake the device (Wake-on-LAN; requires support)'
    echo ' [5] Inspect common service ports on this device'
    echo ' [6] Remote desktop (RDP / VNC / SPICE) via Remmina'
    echo ' [0] Back to main menu'
    printf '\nAction > '
    IFS= read -r action || return
    case "$action" in
      1)
        header
        echo "=== CONNECTIVITY: $target ==="
        if have_cmd ping; then ping -c 4 -W 2 -- "$target"; else echo 'ping command not installed.'; fi
        pause
        ;;
      2)
        header
        echo "=== OPEN WEB INTERFACE: $target ==="
        echo 'Choose a common web-management address. The device must actually provide a web interface.'
        echo ' [1] http://IP/'
        echo ' [2] https://IP/'
        echo ' [3] http://IP:8080/'
        echo ' [4] https://IP:8443/'
        printf 'Choice > '
        IFS= read -r port || continue
        case "$port" in
          1) url="http://$target/" ;;
          2) url="https://$target/" ;;
          3) url="http://$target:8080/" ;;
          4) url="https://$target:8443/" ;;
          *) echo 'Invalid choice.'; pause; continue ;;
        esac
        if have_cmd xdg-open; then
          echo "Opening $url in your default browser..."
          xdg-open "$url" >/dev/null 2>&1 &
          disown 2>/dev/null || true
        else
          echo "Open this address manually: $url"
        fi
        pause
        ;;
      3)
        header
        echo "=== SSH CONNECTION: $target ==="
        if ! have_cmd ssh; then
          echo 'SSH client is missing. Install it with: sudo apt install openssh-client'
          pause; continue
        fi
        echo 'SSH must already be enabled on the target device.'
        echo 'Host-key verification remains enabled; use your own valid account or SSH key.'
        printf 'Username on %s (or q to cancel) > ' "$target"
        IFS= read -r username || continue
        [[ "$username" =~ ^[Qq]$ ]] && continue
        if [[ ! "$username" =~ ^[a-zA-Z_][a-zA-Z0-9_.-]*\$?$ ]]; then
          echo 'Invalid username format.'; pause; continue
        fi
        printf '\nConnecting. Authentication is handled by OpenSSH; VeyraScope does not store passwords.\n\n'
        ssh -o ConnectTimeout=6 -- "$username@$target"
        pause
        ;;
      4)
        header
        echo "=== WAKE-ON-LAN: $target ==="
        mac=''
        if [[ -s "$DISCOVERY_FILE" ]]; then
          mac="$(awk -v target="$target" '$1 == target && $2 ~ /:/ { n=split($2,a,":"); if (n==6) { print tolower($2); exit } }' "$DISCOVERY_FILE")"
        fi
        if [[ ! "$mac" =~ ^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$ ]]; then
          echo 'A MAC address was not saved for this device.'
          echo 'Run option 3 again with arp-scan available; remote-subnet devices may not reveal a MAC.'
          pause; continue
        fi
        printf 'Saved MAC address: %s\n' "$mac"
        echo 'This sends a standard Wake-on-LAN magic packet; it does not bypass device security.'
        echo 'The device must support WoL and have it enabled; Wi-Fi WoL is often unsupported.'
        printf 'Type WAKE to send the packet, or anything else to cancel > '
        IFS= read -r confirm || confirm=''
        if [[ "$confirm" != 'WAKE' ]]; then echo 'Cancelled.'; pause; continue; fi
        if have_cmd wakeonlan; then
          wakeonlan "$mac"
        elif have_cmd etherwake; then
          iface="$(ip -4 route show default 2>/dev/null | awk 'NR==1 {print $5}')"
          if [[ -z "$iface" ]]; then echo 'Could not determine a network interface.'
          elif (( EUID == 0 )); then etherwake -i "$iface" "$mac"
          elif have_cmd sudo; then sudo etherwake -i "$iface" "$mac"
          else echo 'Install wakeonlan or etherwake; root permission may be required.'; fi
        else
          echo 'No Wake-on-LAN sender found. Install one: sudo apt install wakeonlan'
        fi
        pause
        ;;
      5)
        header
        echo "=== COMMON SERVICE CHECK: $target ==="
        if ! have_cmd nmap; then
          echo 'Nmap is required. Install: sudo apt install nmap'; pause; continue
        fi
        echo 'This checks a small list of common ports on this one selected device.'
        echo 'Use only devices you own or are authorized to inspect.'
        printf 'Type SCAN to continue, or anything else to cancel > '
        IFS= read -r confirm || confirm=''
        if [[ "$confirm" != 'SCAN' ]]; then echo 'Cancelled.'; pause; continue; fi
        need_downloads
        local control_scan_file="${DOWNLOADS}/veyrascope-${target}-services.txt"
        nmap -sV --version-light -T2 --max-retries 1 --host-timeout 45s \
          -p '22,23,53,80,81,443,445,554,631,8008,8009,8080,8443,8554,9100,5000,5001,32400' \
          -oN "$control_scan_file" -- "$target"
        printf '\nService report saved to: %s\n' "$control_scan_file"
        pause
        ;;
      6)
        header
        echo "=== REMOTE DESKTOP: $target ==="
        if ! have_cmd remmina; then
          echo 'Remmina is not installed. Install it with: sudo apt install remmina'
          pause; continue
        fi
        echo 'The target must already have a supported remote service enabled (RDP, VNC, or SPICE).'
        echo 'Use this only for a device you own or are authorized to administer.'
        echo ' [1] RDP (usually Windows Remote Desktop)'
        echo ' [2] VNC'
        echo ' [3] SPICE (usually virtual machines)'
        printf 'Protocol > '
        local protocol
        IFS= read -r protocol || continue
        case "$protocol" in
          1) url="rdp://$target" ;;
          2) url="vnc://$target" ;;
          3) url="spice://$target" ;;
          *) echo 'Invalid protocol.'; pause; continue ;;
        esac
        printf 'Opening Remmina for %s. The application handles any required credentials.\n' "$url"
        remmina -c "$url" >/dev/null 2>&1 &
        disown 2>/dev/null || true
        pause
        ;;
      7)
        header
        echo "=== READ-ONLY REMOTE DIAGNOSTICS: $target ==="
        if ! have_cmd ssh; then
          echo 'SSH client is missing. Install: sudo apt install openssh-client'
          pause; continue
        fi
        echo 'SSH must already be enabled on the target; use your own authorized account.'
        printf 'Username on %s (or q to cancel) > ' "$target"
        IFS= read -r username || continue
        [[ "$username" =~ ^[Qq]$ ]] && continue
        if [[ ! "$username" =~ ^[a-zA-Z_][a-zA-Z0-9_.-]*\$?$ ]]; then
          echo 'Invalid username format.'; pause; continue
        fi
        echo
        echo ' [1] Hostname and OS (hostnamectl)'
        echo ' [2] Kernel and architecture (uname -a)'
        echo ' [3] Memory (free -h)'
        echo ' [4] Disk space (df -h)'
        echo ' [5] Uptime and load (uptime)'
        echo ' [6] Network addresses (ip -brief address)'
        printf 'Diagnostic > '
        local diag_choice remote_cmd
        IFS= read -r diag_choice || continue
        case "$diag_choice" in
          1) remote_cmd='hostnamectl' ;;
          2) remote_cmd='uname -a' ;;
          3) remote_cmd='free -h' ;;
          4) remote_cmd='df -h' ;;
          5) remote_cmd='uptime' ;;
          6) remote_cmd='ip -brief address' ;;
          *) echo 'Invalid choice.'; pause; continue ;;
        esac
        echo
        echo "Running approved read-only command: $remote_cmd"
        echo 'OpenSSH handles authentication; VeyraScope does not store passwords.'
        ssh -o ConnectTimeout=6 -- "$username@$target" "$remote_cmd"
        pause
        ;;
      8)
        header
        echo "=== DEVICE NOTE: $target ==="
        need_downloads
        printf 'Enter a short note (single line, blank to cancel) > '
        local note
        IFS= read -r note || note=''
        if [[ -n "$note" ]]; then
          # Strip control characters and keep notes to one short line.
          note="${note//$'\r'/ }"
          note="${note//$'\n'/ }"
          note="${note:0:240}"
          printf '%s\t%s\t%s\n' "$(date '+%F %T')" "$target" "$note" >> "$NOTES_FILE"
          echo "Note saved to: $NOTES_FILE"
        else
          echo 'Cancelled.'
        fi
        pause
        ;;
      0) return ;;
      *) echo 'Unknown action.'; sleep 1 ;;
    esac
  done
}


install_optional_tools() {
  header
  echo '=== INSTALL OPTIONAL VEYRASCOPE TOOLS ==='
  echo 'For Linux Mint / Ubuntu. This uses apt and may ask for your system password.'
  echo 'Packages include discovery, Bluetooth, SSH, Wake-on-LAN and remote desktop tools.'
  echo 'Nothing is installed until you explicitly confirm.'
  printf '\nType INSTALL to continue, or anything else to cancel > '
  local confirm
  IFS= read -r confirm || confirm=''
  if [[ "$confirm" != 'INSTALL' ]]; then echo 'Cancelled.'; pause; return; fi
  if ! have_cmd apt; then echo 'apt was not found. This installer is intended for Linux Mint / Ubuntu.'; pause; return; fi
  sudo apt update && sudo apt install -y nmap arp-scan avahi-utils bluez gupnp-tools curl libxml2-utils iproute2 openssh-client wakeonlan remmina
  echo
  echo 'Tool installation finished. If any package failed, read apt output above.'
  pause
}

while true; do
  header
  printf '  %s[1]%s Characteristics of this computer\n' "$green" "$reset"
  printf '  %s[2]%s Network details and discovered service names\n' "$green" "$reset"
  printf '  %s[3]%s Find nearby LAN devices (IP / MAC vendor / names)\n' "$green" "$reset"
  printf '  %s[4]%s Find nearby Bluetooth devices (optional scan)\n' "$green" "$reset"
  printf '  %s[5]%s Deeper OS/service/model clues for found devices\n' "$green" "$reset"
  printf '  %s[6]%s Services listening on this computer\n' "$green" "$reset"
  printf '  %s[7]%s Save full report to Downloads\n' "$green" "$reset"
  printf '  %s[8]%s Explore details for one discovered device\n' "$green" "$reset"
  printf '  %s[9]%s Check optional discovery tools\n' "$green" "$reset"
  printf '  %s[10]%s Manage a discovered device (web / SSH / Wake-on-LAN / remote desktop)\n' "$green" "$reset"
  printf '  %s[11]%s Install optional tools (apt; asks for confirmation)\n' "$green" "$reset"
  printf '  %s[12]%s Compare latest and previous LAN scans\n' "$green" "$reset"
  printf '  %s[13]%s Export device inventory as CSV\n' "$green" "$reset"
  printf '  %s[14]%s Monitor one discovered device for 30 seconds\n' "$green" "$reset"
  printf '  %s[15]%s Wake a device by a known MAC address (Wake-on-LAN)\n' "$green" "$reset"
  printf '  %s[0]%s Exit\n\n' "$green" "$reset"
  printf 'Select > '
  IFS= read -r choice || break
  case "$choice" in
    1) local_system ;;
    2) network_info ;;
    3) nearby_devices ;;
    4) bluetooth_discovery ;;
    5) fingerprint_devices ;;
    6) local_services ;;
    7) save_report ;;
    8) device_details ;;
    9) check_tools ;;
    10) control_device ;;
    11) install_optional_tools ;;
    12) compare_scans ;;
    13) export_inventory_csv ;;
    14) monitor_device ;;
    15) wake_by_mac ;;
    0) clear 2>/dev/null || true; exit 0 ;;
    *) printf '\n%s\n' "${yellow}Unknown option.${reset}"; sleep 1 ;;
  esac
done
