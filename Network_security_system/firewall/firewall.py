import socket

# Simple packet filter firewall
class Firewall:
    def __init__(self):
        self.rules = []

    def add_rule(self, src_ip=None, dest_ip=None, action="ALLOW"):
        rule = {
            'src_ip': src_ip,
            'dest_ip': dest_ip,
            'action': action
        }
        self.rules.append(rule)

    def check_packet(self, packet):
        src_ip, dest_ip = packet
        for rule in self.rules:
            if (rule['src_ip'] == src_ip or rule['src_ip'] is None) and (rule['dest_ip'] == dest_ip or rule['dest_ip'] is None):
                return rule['action']
        return "DENY"

# Simulated network packet traffic
firewall = Firewall()
firewall.add_rule(src_ip="192.168.1.10", action="ALLOW")
firewall.add_rule(dest_ip="10.0.0.5", action="BLOCK")

# Example packets
packets = [("192.168.1.10", "10.0.0.5"), ("10.0.0.20", "10.0.0.5")]

for packet in packets:
    action = firewall.check_packet(packet)
    print(f"Packet from {packet[0]} to {packet[1]}: {action}")
