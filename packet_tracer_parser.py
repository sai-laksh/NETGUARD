"""
NETGUARD - Smart Campus Network Monitoring and Security System
Cisco Packet Tracer Topology Parser (packet_tracer_parser.py)

This module loads Cisco Packet Tracer network models and exports,
extracting device nodes, VLAN subnets, interface links, and connectivity states.
"""

import os
import json

class PacketTracerParser:
    def __init__(self, topology_path="data/packet_tracer_topology.json"):
        self.topology_path = topology_path

    def load_topology(self, filepath=None):
        target_path = filepath or self.topology_path
        if not os.path.exists(target_path):
            return {"error": f"Topology file not found: {target_path}"}

        with open(target_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        segments = data.get("segments", [])
        links = data.get("links", [])

        # Categorize links
        up_links = [l for l in links if l.get("status") == "UP"]
        warn_links = [l for l in links if l.get("status") == "WARNING"]
        down_links = [l for l in links if l.get("status") == "DOWN"]

        return {
            "topologyName": data.get("topologyName", "Campus Network"),
            "total_segments": len(segments),
            "total_links": len(links),
            "link_summary": {
                "up": len(up_links),
                "warning": len(warn_links),
                "down": len(down_links)
            },
            "segments": segments,
            "links": links,
            "integration_ready": True
        }

if __name__ == "__main__":
    parser = PacketTracerParser()
    res = parser.load_topology()
    print("Packet Tracer Parser Test Result:")
    print(json.dumps(res, indent=2))
