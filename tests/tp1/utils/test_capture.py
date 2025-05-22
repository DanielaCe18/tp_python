from src.tp1.utils.capture import Capture
from scapy.all import ARP, IP, TCP, Raw


def test_summary_structure():
    cap = Capture()
    cap.packets = []
    cap._analyze_protocols()
    cap._detect_attacks()
    summary = cap.get_summary()

    assert isinstance(summary, dict)
    assert "protocols" in summary
    assert "attacks" in summary
    assert "packet_count" in summary
    assert isinstance(summary["protocols"], dict)
    assert isinstance(summary["attacks"], list)


def test_sql_injection_detection():
    pkt = IP(src="10.0.0.1") / TCP(dport=80) / Raw(load=b"GET /?id=1 OR 1=1-- HTTP/1.1\r\n\r\n")
    cap = Capture()
    cap.packets = [pkt]
    cap._analyze_protocols()
    cap._detect_attacks()
    summary = cap.get_summary()

    assert "HTTP" in summary["protocols"]
    assert any(a["type"] == "SQL Injection" for a in summary["attacks"])


def test_arp_spoofing_detection():
    pkt1 = ARP(psrc="192.168.1.5", hwsrc="00:11:22:33:44:55")
    pkt2 = ARP(psrc="192.168.1.5", hwsrc="AA:BB:CC:DD:EE:FF")
    cap = Capture()
    cap.packets = [pkt1, pkt2]
    cap._analyze_protocols()
    cap._detect_attacks()
    summary = cap.get_summary()

    assert summary["protocols"]["ARP"] == 2
    assert any(a["type"] == "ARP Spoofing" for a in summary["attacks"])


def test_dos_attack_detection():
    # Simule 80 paquets venant d'une même IP
    pkts = [IP(src="192.168.1.100") / TCP(dport=80) for _ in range(80)]
    pkts += [IP(src="10.0.0.2") / TCP(dport=443) for _ in range(20)]
    cap = Capture(packet_count=100)
    cap.packets = pkts
    cap._analyze_protocols()
    cap._detect_attacks()
    summary = cap.get_summary()

    assert any(a["type"] == "DoS suspect" for a in summary["attacks"])
    assert summary["top_ips"][0][0] == "192.168.1.100"
