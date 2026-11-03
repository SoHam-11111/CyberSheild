from collections import defaultdict, deque
from datetime import datetime, timedelta
import threading


class DetectionEngine:

    def __init__(self):
        self.lock = threading.Lock()

        self.packet_events = defaultdict(deque)
        self.port_events = defaultdict(deque)
        self.connection_events = defaultdict(deque)

        self.alerts = []
        self.max_alerts = 200

        self.ddos_threshold = 100
        self.port_scan_threshold = 15
        self.connection_threshold = 30

        self.window_seconds = 10

    def _clean_old_events(self, events, current_time):
        cutoff = current_time - timedelta(
            seconds=self.window_seconds
        )

        while events and events[0][0] < cutoff:
            events.popleft()

    def _add_alert(self, alert_type, source_ip,
                   description, severity):

        alert = {
            "timestamp": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "type": alert_type,
            "source_ip": source_ip,
            "description": description,
            "severity": severity
        }

        self.alerts.insert(0, alert)

        if len(self.alerts) > self.max_alerts:
            self.alerts.pop()

    def process_packet(self, source_ip, destination_ip,
                       source_port, destination_port,
                       protocol, packet_size,
                       tcp_flags=0):

        current_time = datetime.now()

        with self.lock:

            # Rule 1: High-volume traffic
            # Track traffic separately for each source-destination pair.

            traffic_key = (source_ip, destination_ip)
            events = self.packet_events[traffic_key]

            events.append((current_time, packet_size))

            self._clean_old_events(events, current_time)

            if len(events) == self.ddos_threshold + 1:

                self._add_alert(
                    "Possible DDoS",
                    source_ip,
                    "High packet volume detected between "
                    + source_ip + " and " + destination_ip
                    + ": " + str(len(events))
                    + " packets within 10 seconds.",
                    "High"
                )

            # Only initial TCP SYN packets are used
            # for connection-based detection.

            is_initial_syn = (
                protocol == "TCP"
                and (int(tcp_flags) & 0x02) != 0
                and (int(tcp_flags) & 0x10) == 0
            )

            if is_initial_syn:

                # Rule 2: Possible Port Scan

                port_events = self.port_events[source_ip]

                port_events.append(
                    (current_time, destination_port)
                )

                self._clean_old_events(
                    port_events, current_time
                )

                distinct_ports = set(
                    event[1] for event in port_events
                )

                if len(distinct_ports) == self.port_scan_threshold + 1:

                    self._add_alert(
                        "Possible Port Scan",
                        source_ip,
                        "Initial TCP connection attempts "
                        "observed on "
                        + str(len(distinct_ports))
                        + " distinct destination ports.",
                        "Medium"
                    )

                # Rule 3: Repeated Connection Attempts

                connection_key = (
                    source_ip,
                    destination_ip,
                    destination_port
                )

                connection_events = (
                    self.connection_events[connection_key]
                )

                connection_events.append(
                    (current_time, source_port)
                )

                self._clean_old_events(
                    connection_events, current_time
                )

                if len(connection_events) == self.connection_threshold + 1:

                    self._add_alert(
                        "Repeated Connections",
                        source_ip,
                        "Repeated TCP connection attempts to "
                        + destination_ip
                        + ":" + str(destination_port),
                        "Medium"
                    )

    def get_alerts(self):

        with self.lock:
            return list(self.alerts)

    def get_alert_count(self):

        with self.lock:
            return len(self.alerts)