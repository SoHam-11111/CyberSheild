from scapy.all import AsyncSniffer, IP, TCP, UDP
from datetime import datetime
from collections import deque
from monitoring.detection_engine import DetectionEngine
import threading
import json
import os


class PacketMonitor:

    def __init__(self, interface="Wi-Fi"):
        self.interface = interface
        self.engine = DetectionEngine()

        self.sniffer = None
        self.running = False
        self.packet_count = 0

        self.lock = threading.Lock()
        self.recent_traffic = deque(maxlen=200)

        self.log_directory = "logs"

        if not os.path.exists(self.log_directory):
            os.makedirs(self.log_directory)

        self.log_file = os.path.join(
            self.log_directory,
            "live_traffic.jsonl"
        )

    def process_packet(self, packet):

        if IP not in packet:
            return

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        packet_size = len(packet)

        protocol = "OTHER"
        source_port = 0
        destination_port = 0
        tcp_flags = 0

        if TCP in packet:
            protocol = "TCP"
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport
            tcp_flags = int(packet[TCP].flags)

        elif UDP in packet:
            protocol = "UDP"
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        self.engine.process_packet(
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol,
            packet_size,
            tcp_flags
        )

        record = {
            "timestamp": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "source_port": source_port,
            "destination_port": destination_port,
            "protocol": protocol,
            "packet_size": packet_size
        }

        with self.lock:

            self.packet_count += 1

            self.recent_traffic.appendleft(record)

            with open(self.log_file, "a") as file:
                file.write(json.dumps(record) + "\n")

    def start(self):

        with self.lock:

            if self.running:
                return False

            self.running = True

            try:
                self.sniffer = AsyncSniffer(
                    iface=self.interface,
                    filter="ip",
                    prn=self.process_packet,
                    store=False
                )

                self.sniffer.start()
                return True

            except Exception:
                self.running = False
                self.sniffer = None
                raise

    def stop(self):

        with self.lock:

            if not self.running:
                return False

            sniffer = self.sniffer
            self.running = False

        if sniffer is not None:

            try:
                sniffer.stop()
            except Exception:
                pass

        with self.lock:
            self.sniffer = None

        return True

    def get_status(self):

        with self.lock:
            return {
                "running": self.running,
                "packet_count": self.packet_count,
                "interface": self.interface
            }

    def get_alerts(self):
        return self.engine.get_alerts()

    def get_recent_traffic(self):

        with self.lock:
            return list(self.recent_traffic)