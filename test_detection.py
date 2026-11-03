from monitoring.detection_engine import DetectionEngine


def main():

    engine = DetectionEngine()

    print("CYBERSHIELD DETECTION ENGINE TEST")
    print("=" * 45)

    source_ddos = "192.168.1.100"
    destination_ddos = "10.0.0.10"

    source_scan = "192.168.1.200"
    destination_scan = "10.0.0.20"

    source_repeat = "192.168.1.150"
    destination_repeat = "10.0.0.30"

    print("\n[TEST 1] Simulating high-volume traffic...")

    for i in range(101):
        engine.process_packet(
            source_ddos,
            destination_ddos,
            5000,
            80,
            "TCP",
            100,
            0x02
        )

    print("[TEST 2] Simulating TCP SYN port scanning...")

    for port in range(20, 36):
        engine.process_packet(
            source_scan,
            destination_scan,
            40000 + port,
            port,
            "TCP",
            60,
            0x02
        )

    print("[TEST 3] Simulating repeated TCP SYN connections...")

    for i in range(31):
        engine.process_packet(
            source_repeat,
            destination_repeat,
            45000 + i,
            8080,
            "TCP",
            60,
            0x02
        )

    print("\n" + "=" * 45)
    print("GENERATED SECURITY ALERTS")
    print("=" * 45)

    alerts = engine.get_alerts()

    for alert in alerts:
        print("\nType:", alert["type"])
        print("Source IP:", alert["source_ip"])
        print("Severity:", alert["severity"])
        print("Description:", alert["description"])
        print("Timestamp:", alert["timestamp"])

    print("\nTotal alerts:", len(alerts))

    expected = {
        "Possible DDoS",
        "Possible Port Scan",
        "Repeated Connections"
    }

    actual = set(alert["type"] for alert in alerts)

    if expected.issubset(actual):
        print("\nRESULT: ALL THREE DETECTION TESTS PASSED")
    else:
        print("\nRESULT: SOME DETECTION TESTS FAILED")


if __name__ == "__main__":
    main()