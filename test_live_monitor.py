from monitoring.packet_monitor import PacketMonitor
import time
import json
import os

monitor = PacketMonitor(interface="Wi-Fi")

print("======================================")
print(" CYBERSHIELD LIVE NETWORK MONITOR")
print("======================================")

print("\nStarting live packet capture...")
monitor.start()

print("Monitoring interface:", monitor.interface)
print("Generate network traffic by opening a few websites.")
print("Capture duration: 30 seconds")

try:
    for remaining in range(30, 0, -1):
        print("Remaining:", remaining, "seconds")
        time.sleep(1)

except KeyboardInterrupt:
    print("\nMonitoring interrupted.")

finally:
    monitor.stop()
    time.sleep(2)

print("\n======================================")
print(" LIVE MONITORING RESULTS")
print("======================================")

print("Status:", monitor.get_status())

alerts = monitor.get_alerts()

print("\nSecurity alerts:", len(alerts))

for alert in alerts:
    print("\nAlert:", alert["type"])
    print("Source:", alert["source_ip"])
    print("Severity:", alert["severity"])
    print("Description:", alert["description"])

if os.path.exists(monitor.log_file):

    print("\nTraffic log:", monitor.log_file)

    with open(monitor.log_file, "r") as file:
        records = file.readlines()

    print("Logged packet records:", len(records))

    if records:
        print("\nSample traffic record:")
        print(json.dumps(json.loads(records[-1]), indent=4))

else:
    print("\nNo traffic log was created.")