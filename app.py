from flask import Flask, render_template, jsonify, request
from impala.dbapi import connect
from monitoring.packet_monitor import PacketMonitor
import threading

app = Flask(__name__)

# Impala connection settings
IMPALA_HOST = "127.0.0.1"
IMPALA_PORT = 21050
DATABASE = "cybershield_db"
TABLE = "security_incidents"

# Live monitoring configuration
monitor = PacketMonitor(interface="Wi-Fi")


def get_connection():
    return connect(
        host=IMPALA_HOST,
        port=IMPALA_PORT,
        auth_mechanism="NOSASL",
        use_ssl=False
    )


def get_incidents_from_impala():
    connection = get_connection()

    try:
        cursor = connection.cursor()

        cursor.execute(
            "SELECT * FROM {}.{}".format(DATABASE, TABLE)
        )

        columns = [column[0].lower() for column in cursor.description]
        rows = cursor.fetchall()

        incidents = []

        for row in rows:
            record = dict(zip(columns, row))

            incident = {
                "id": record.get("id", record.get("incident_id", "")),
                "threat_type": record.get("threat_type", ""),
                "source_ip": record.get(
                    "source_ip",
                    record.get("source_ip_address", "")
                ),
                "severity": record.get("severity", ""),
                "status": record.get("status", "")
            }

            incidents.append(incident)

        return incidents

    finally:
        connection.close()


def count_by(field, records):
    result = {}

    for incident in records:
        key = incident[field]
        result[key] = result.get(key, 0) + 1

    return result


@app.route("/")
def dashboard():
    return render_template("index.html")


# -----------------------------------------
# EXISTING HISTORICAL INCIDENT API
# -----------------------------------------

@app.route("/api/incidents")
def get_incidents():
    try:
        records = get_incidents_from_impala()

        severity = request.args.get("severity", "")
        status = request.args.get("status", "")
        threat_type = request.args.get("threat_type", "")
        search = request.args.get("search", "").lower()

        if severity:
            records = [
                r for r in records
                if str(r["severity"]) == severity
            ]

        if status:
            records = [
                r for r in records
                if str(r["status"]) == status
            ]

        if threat_type:
            records = [
                r for r in records
                if str(r["threat_type"]) == threat_type
            ]

        if search:
            records = [
                r for r in records
                if search in str(r["id"]).lower()
                or search in str(r["threat_type"]).lower()
                or search in str(r["source_ip"]).lower()
                or search in str(r["severity"]).lower()
                or search in str(r["status"]).lower()
            ]

        return jsonify({
            "total": len(records),
            "critical": sum(
                1 for r in records
                if str(r["severity"]).lower() == "critical"
            ),
            "detected": sum(
                1 for r in records
                if str(r["status"]).lower() == "detected"
            ),
            "blocked": sum(
                1 for r in records
                if str(r["status"]).lower() == "blocked"
            ),
            "threat_types": count_by("threat_type", records),
            "severities": count_by("severity", records),
            "statuses": count_by("status", records),
            "incidents": records
        })

    except Exception as error:
        app.logger.exception("Failed to retrieve incidents from Impala")

        return jsonify({
            "error": "Unable to retrieve incident data from Impala.",
            "details": str(error)
        }), 500


# -----------------------------------------
# LIVE MONITORING APIs
# -----------------------------------------

@app.route("/api/monitor/start", methods=["POST"])
def start_monitoring():

    try:
        started = monitor.start()

        return jsonify({
            "success": True,
            "message": (
                "Live monitoring started."
                if started
                else "Live monitoring is already running."
            ),
            "status": monitor.get_status()
        })

    except Exception as error:
        app.logger.exception("Failed to start live monitoring")

        return jsonify({
            "success": False,
            "error": str(error)
        }), 500


@app.route("/api/monitor/stop", methods=["POST"])
def stop_monitoring():

    try:
        stopped = monitor.stop()

        return jsonify({
            "success": True,
            "message": (
                "Live monitoring stopped."
                if stopped
                else "Live monitoring is already stopped."
            ),
            "status": monitor.get_status()
        })

    except Exception as error:
        app.logger.exception("Failed to stop live monitoring")

        return jsonify({
            "success": False,
            "error": str(error)
        }), 500


@app.route("/api/monitor/status")
def monitoring_status():

    return jsonify(monitor.get_status())


@app.route("/api/monitor/traffic")
def live_traffic():

    return jsonify({
        "total": monitor.get_status()["packet_count"],
        "traffic": monitor.get_recent_traffic()
    })


@app.route("/api/monitor/alerts")
def live_alerts():

    alerts = monitor.get_alerts()

    return jsonify({
        "total": len(alerts),
        "alerts": alerts
    })


if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        threaded=True
    )