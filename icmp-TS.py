import ipaddress
import argparse
from scapy.all import IP, ICMP, sr1, conf
from datetime import timedelta

# ANSI color codes
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def expand_targets(ip=None, ip_list=None):
    targets = set()
    if ip:
        try:
            if '/' in ip:
                targets.update(str(host) for host in ipaddress.ip_network(ip, strict=False).hosts())
            else:
                targets.add(ip)
        except ValueError as e:
            print(f"Invalid IP or CIDR: {ip} ({e})")
    if ip_list:
        try:
            with open(ip_list, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        if '/' in line:
                            targets.update(str(host) for host in ipaddress.ip_network(line, strict=False).hosts())
                        else:
                            targets.add(line)
        except FileNotFoundError:
            print(f"File not found: {ip_list}")
    return list(targets)

def format_time(ms):
    return str(timedelta(milliseconds=ms)).rstrip('0').rstrip('.')  # Clean trailing zeros

def test_icmp_timestamp(target, verbose=False):
    pkt = IP(dst=target)/ICMP(type=13)
    reply = sr1(pkt, timeout=2, verbose=0)

    if reply and ICMP in reply and reply[ICMP].type == 14:
        ip_layer = reply[IP]
        icmp_layer = reply[ICMP]

        ts_ori = format_time(icmp_layer.ts_ori)
        ts_rx = format_time(icmp_layer.ts_rx)
        ts_tx = format_time(icmp_layer.ts_tx)

        if verbose:
            print(reply.summary())
            reply.show()
        else:
            print(f"[{GREEN}{target}{RESET}] dst={ip_layer.dst}")
            print(f"           ICMP type={icmp_layer.type} (timestamp-reply)")
            print(f"           ts_ori={YELLOW}{ts_ori} UTC{RESET}  "
                  f"ts_rx={YELLOW}{ts_rx} UTC{RESET}  "
                  f"ts_tx={YELLOW}{ts_tx} UTC{RESET}")
    else:
        print(f"{GREEN}[{target}]{RESET} No ICMP timestamp reply or request blocked.")

def main():
    parser = argparse.ArgumentParser(description="ICMP Timestamp Tester")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--ip", help="Single IP address or CIDR range")
    group.add_argument("-l", "--list", help="File with IPs or CIDR ranges")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output (Scapy .show())")

    args = parser.parse_args()
    targets = expand_targets(ip=args.ip, ip_list=args.list)
    if not targets:
        print("No valid targets provided.")
        return

    for target in targets:
        test_icmp_timestamp(target, verbose=args.verbose)

if __name__ == "__main__":
    conf.verb = 0  # Suppress Scapy's internal chatter
    main()
