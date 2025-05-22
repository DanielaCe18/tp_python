from scapy.all import sniff, ARP, IP, TCP, UDP, Raw
from collections import Counter, defaultdict
import re


class Capture:
    def __init__(self, iface=None, packet_count=10000, timeout=60):
        self.iface = iface
        self.packet_count = packet_count
        self.timeout = timeout
        self.packets = []
        self.protocol_counts = Counter()
        self.port_counts = Counter()
        self.ip_traffic = Counter()
        self.attacks = []

    def capture_trafic(self):
        self.packets = sniff(iface=self.iface, count=self.packet_count, timeout=self.timeout)
        self._analyze_protocols()
        self._detect_attacks()

    def _analyze_protocols(self):
        for pkt in self.packets:
            proto = self._get_proto(pkt)
            self.protocol_counts[proto] += 1

            if pkt.haslayer(TCP) or pkt.haslayer(UDP):
                sport = pkt.sport
                dport = pkt.dport
                self.port_counts[sport] += 1
                self.port_counts[dport] += 1

            if pkt.haslayer(IP):
                self.ip_traffic[pkt[IP].src] += 1

    def _get_proto(self, pkt):
        if pkt.haslayer(ARP):
            return "ARP"
        elif pkt.haslayer(IP):
            if pkt.haslayer(TCP):
                dport = pkt[TCP].dport
                if dport == 80:
                    return "HTTP"
                elif dport == 443:
                    return "HTTPS"
                elif dport == 21:
                    return "FTP"
                elif dport == 22:
                    return "SSH"
                elif dport == 3306:
                    return "MySQL"
                return "TCP"
            elif pkt.haslayer(UDP):
                dport = pkt[UDP].dport
                if dport == 53:
                    return "DNS"
                return "UDP"
            return f"IP({pkt[IP].proto})"
        return "OTHER"

    def _detect_attacks(self):
        seen_arp = {}
        ip_hits = defaultdict(int)

        for pkt in self.packets:
            # --- ARP Spoofing ---
            if pkt.haslayer(ARP):
                ip = pkt[ARP].psrc
                mac = pkt[ARP].hwsrc
                if ip in seen_arp and seen_arp[ip] != mac:
                    self.attacks.append({
                        "type": "ARP Spoofing",
                        "ip": ip,
                        "mac": mac,
                        "description": f"Conflit ARP : {ip} a été vu avec plusieurs MAC (potentiel spoof)"
                    })
                else:
                    seen_arp[ip] = mac

            # --- SQL Injection ---
            if pkt.haslayer(Raw):
                payload = pkt[Raw].load.decode(errors="ignore").lower()
                if re.search(r"(select\s.+\sfrom|union\s+select|drop\s+table|--|')", payload):
                    self.attacks.append({
                        "type": "SQL Injection",
                        "ip": pkt[IP].src if pkt.haslayer(IP) else "unknown",
                        "mac": pkt.src,
                        "description": f"Payload suspect détecté : {payload[:50]}"
                    })

            # ---DoS Detection (même IP spammant) ---
            if pkt.haslayer(IP):
                ip_hits[pkt[IP].src] += 1

        for ip, count in ip_hits.items():
            if count > self.packet_count * 0.5:  # Plus de 50% des paquets viennent de cette IP
                self.attacks.append({
                    "type": "DoS suspect",
                    "ip": ip,
                    "description": f"IP {ip} a généré {count} paquets ({int(100 * count / self.packet_count)}%)"
                })

    def analyse(self, proto_filter=None):
        if proto_filter:
            self.packets = [p for p in self.packets if self._get_proto(p).lower() == proto_filter.lower()]

    def get_summary(self):
        return {
            "protocols": dict(self.protocol_counts),
            "top_ports": self.port_counts.most_common(5),
            "top_ips": self.ip_traffic.most_common(5),
            "attacks": self.attacks,
            "packet_count": len(self.packets),
        }
