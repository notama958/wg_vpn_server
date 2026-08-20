#!/usr/bin/env python3

import os
import glob
import statistics
from collections import defaultdict
from dataclasses import dataclass
from typing import List, Tuple, Optional, Dict, Any
from scapy.all import PcapReader, IP, TCP, UDP, Packet

PCAP_DIR = os.path.expanduser("./pcaps")
TUNNEL_NET = "10.66.0."
WINDOW_SIZE = 40

@dataclass
class FlowFeatures:
    """Statistical features extracted from a time window of packets."""
    mean_sz: float
    std_sz: float
    min_sz: float
    max_sz: float
    mean_iat: float
    std_iat: float
    pps: float
    bps: float
    up_dn: float
    
class PcapParser:
    """
    Parse PCAP files and extract per‑flow statistical features
    from sliding time‑windows.
    """

    @staticmethod
    def _flow_key(packet: Packet) -> Optional[Tuple[int, Tuple[str, int], Tuple[str, int]]]:
        """
        Generate a bidirectional flow key: (protocol, (src_ip, src_port), (dst_ip, dst_port))
        Returns None if the packet is not TCP or UDP (ports missing).
        """
        if IP not in packet:
            return None
        ip = packet[IP]

        # Extract ports only for TCP/UDP
        if TCP in packet:
            sport, dport = packet[TCP].sport, packet[TCP].dport
        elif UDP in packet:
            sport, dport = packet[UDP].sport, packet[UDP].dport
        else:
            return None  # skip other protocols

        src = (ip.src, sport)
        dst = (ip.dst, dport)
        # Sort endpoints so the flow is directionless
        return (ip.proto,) + tuple(sorted([src, dst]))

    @staticmethod
    def _extract_features(window: List[Tuple[float, int, int]]) -> FlowFeatures:
        """
        Compute statistical features from a list of packet records.
        Each record: (timestamp, packet_length, direction)
        direction = +1 for tunnel->outside, -1 for outside->tunnel.
        """
        # Sort by timestamp (first element)
        window_sorted = sorted(window, key=lambda x: x[0])
        times = [t for t, _, _ in window_sorted]
        sizes = [s for _, s, _ in window_sorted]
        directions = [d for _, _, d in window_sorted]

        # Inter‑arrival times
        iats = [b - a for a, b in zip(times, times[1:])]

        # Total bytes upstream (positive direction) and downstream (negative)
        up_bytes = sum(s for s, d in zip(sizes, directions) if d > 0)
        down_bytes = sum(s for s, d in zip(sizes, directions) if d < 0)

        duration = max(1e-3, times[-1] - times[0])  # avoid division by zero

        return FlowFeatures(
            mean_sz=statistics.mean(sizes),
            std_sz=statistics.pstdev(sizes),
            min_sz=min(sizes),
            max_sz=max(sizes),
            mean_iat=statistics.mean(iats) if iats else 0.0,
            std_iat=statistics.pstdev(iats) if iats else 0.0,
            pps=len(window) / duration,
            bps=sum(sizes) / duration,
            up_dn=(up_bytes + 1) / (down_bytes + 1)   # smoothing to avoid division by zero
        )

    @classmethod
    def parse(cls,
              pcap_dir: str,
              tunnel_prefix: str,
              window_size: int) -> Tuple[List[FlowFeatures], List[str]]:
        """
        Scan all .pcap files in `pcap_dir`, extract feature windows from each flow,
        and return a list of features together with their corresponding labels.

        Returns:
            X: List of FlowFeatures objects
            y: List of label strings (one per window)
        """
        X: List[FlowFeatures] = []
        y: List[str] = []

        for pcap_path in glob.glob(os.path.join(pcap_dir, "*.pcap")):
            label = os.path.splitext(os.path.basename(pcap_path))[0]
            print(f"Processing {label} ...")

            # Collect packet records per flow
            flows: Dict[Any, List[Tuple[float, int, int]]] = defaultdict(list)

            with PcapReader(pcap_path) as reader:
                for packet in reader:
                    if IP not in packet:
                        continue

                    # Determine direction: 1 if source is inside tunnel network, else -1
                    direction = 1 if packet[IP].src.startswith(tunnel_prefix) else -1

                    key = cls._flow_key(packet)
                    if key is None:
                        continue   # skip non‑TCP/UDP

                    flows[key].append((float(packet.time), len(packet), direction))

            # Extract windows for each flow
            total_windows = 0
            for flow_records in flows.values():
                flow_records.sort(key=lambda x: x[0])   # sort by time
                num_records = len(flow_records)
                # Slide over the flow with step = window_size (non‑overlapping)
                for start in range(0, num_records - window_size + 1, window_size):
                    window = flow_records[start:start + window_size]
                    features = cls._extract_features(window)
                    X.append(features)
                    y.append(label)
                    total_windows += 1

            print(f"Extracted {total_windows} windows from {label}")

        return X, y


if __name__ == "__main__":
    features, labels = PcapParser.parse(PCAP_DIR, TUNNEL_NET, WINDOW_SIZE)
    print(f"\nTotal windows extracted: {len(features)}")