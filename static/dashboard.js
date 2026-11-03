const API_URL = "/api/incidents";

const MONITOR_API = "/api/monitor";

let threatChart;
let severityChart;
let statusChart;

let refreshTimer = null;

Chart.defaults.color = "#8ea1ba";
Chart.defaults.borderColor = "#26364d";
Chart.defaults.font.family = "'Segoe UI', Arial, sans-serif";

const chartColors = {
    blue: "#48a9ff",
    cyan: "#3dd9d0",
    red: "#ff667d",
    orange: "#ffb45e",
    green: "#43d6a3",
    purple: "#a78bfa",
    yellow: "#f5d782",
    slate: "#8294ad"
};

const severityColors = {
    Critical: chartColors.red,
    High: chartColors.orange,
    Medium: chartColors.yellow,
    Low: chartColors.green
};


// -----------------------------------------
// CHART CREATION
// -----------------------------------------

function createCharts() {

    threatChart = new Chart(
        document.getElementById("threatChart"),
        {
            type: "bar",

            data: {
                labels: [],

                datasets: [{
                    label: "Incidents",
                    data: [],
                    backgroundColor: chartColors.blue,
                    borderRadius: 5,
                    maxBarThickness: 30
                }]
            },

            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: "y",

                plugins: {
                    legend: {
                        display: false
                    }
                },

                scales: {
                    x: {
                        beginAtZero: true,
                        ticks: {
                            precision: 0
                        }
                    },

                    y: {
                        grid: {
                            display: false
                        }
                    }
                }
            }
        }
    );


    severityChart = new Chart(
        document.getElementById("severityChart"),
        {
            type: "doughnut",

            data: {
                labels: [],

                datasets: [{
                    data: [],
                    backgroundColor: [],
                    borderColor: "#131f33",
                    borderWidth: 4,
                    hoverOffset: 7
                }]
            },

            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: "66%",

                plugins: {
                    legend: {
                        position: "bottom",

                        labels: {
                            padding: 18,
                            usePointStyle: true
                        }
                    }
                }
            }
        }
    );


    statusChart = new Chart(
        document.getElementById("statusChart"),
        {
            type: "bar",

            data: {
                labels: [],

                datasets: [{
                    label: "Incidents",
                    data: [],

                    backgroundColor: [
                        chartColors.orange,
                        chartColors.blue,
                        chartColors.green,
                        chartColors.purple
                    ],

                    borderRadius: 5,
                    maxBarThickness: 55
                }]
            },

            options: {
                responsive: true,
                maintainAspectRatio: false,

                plugins: {
                    legend: {
                        display: false
                    }
                },

                scales: {
                    y: {
                        beginAtZero: true,

                        ticks: {
                            precision: 0
                        }
                    },

                    x: {
                        grid: {
                            display: false
                        }
                    }
                }
            }
        }
    );
}


function updateChart(chart, labels, values, colors) {

    chart.data.labels = labels;
    chart.data.datasets[0].data = values;

    if (colors) {
        chart.data.datasets[0].backgroundColor = colors;
    }

    chart.update();
}


// -----------------------------------------
// HISTORICAL INCIDENTS
// -----------------------------------------

function severityClass(severity) {

    return "severity-" +
        String(severity).toLowerCase();
}


function statusClass(status) {

    return "status-" +
        String(status).toLowerCase().replace(/\s+/g, "-");
}


function escapeHTML(value) {

    return String(value ?? "").replace(
        /[&<>"']/g,
        character => ({
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;"
        })[character]
    );
}


function renderIncidents(incidents) {

    const tbody = document.getElementById("incidentRows");

    document.getElementById("recordCount").textContent =
        incidents.length + " records";


    if (!incidents.length) {

        tbody.innerHTML = `
            <tr>
                <td colspan="5" class="empty-state">
                    No incidents match the selected filters.
                </td>
            </tr>
        `;

        return;
    }


    tbody.innerHTML = incidents.map(incident => {

        const severity = escapeHTML(incident.severity);
        const status = escapeHTML(incident.status);

        return `
            <tr>
                <td>#${escapeHTML(incident.id)}</td>

                <td>${escapeHTML(incident.threat_type)}</td>

                <td>${escapeHTML(incident.source_ip)}</td>

                <td>
                    <span class="badge ${severityClass(severity)}">
                        ${severity}
                    </span>
                </td>

                <td>
                    <span class="${statusClass(status)}">
                        ${status}
                    </span>
                </td>
            </tr>
        `;

    }).join("");
}


async function loadDashboard() {

    const params = new URLSearchParams();

    const severity =
        document.getElementById("severityFilter").value;

    const status =
        document.getElementById("statusFilter").value;

    const threatType =
        document.getElementById("threatFilter").value;

    const search =
        document.getElementById("searchInput").value.trim();


    if (severity) params.set("severity", severity);
    if (status) params.set("status", status);
    if (threatType) params.set("threat_type", threatType);
    if (search) params.set("search", search);


    try {

        const response = await fetch(
            `${API_URL}?${params.toString()}`
        );

        if (!response.ok) {
            throw new Error("HTTP " + response.status);
        }

        const data = await response.json();


        document.getElementById("total").textContent =
            data.total;

        document.getElementById("critical").textContent =
            data.critical;

        document.getElementById("detected").textContent =
            data.detected;

        document.getElementById("blocked").textContent =
            data.blocked;


        const threatEntries = Object.entries(data.threat_types)
            .sort((a, b) => b[1] - a[1] ||
                a[0].localeCompare(b[0]));


        updateChart(
            threatChart,
            threatEntries.map(item => item[0]),
            threatEntries.map(item => item[1])
        );


        const severityOrder = [
            "Critical",
            "High",
            "Medium",
            "Low"
        ];

        const severityEntries = severityOrder
            .filter(name => data.severities[name] !== undefined)
            .map(name => [name, data.severities[name]]);


        updateChart(
            severityChart,
            severityEntries.map(item => item[0]),
            severityEntries.map(item => item[1]),
            severityEntries.map(item => severityColors[item[0]])
        );


        const statusOrder = [
            "Detected",
            "Investigating",
            "Blocked",
            "Contained"
        ];

        const statusEntries = statusOrder
            .filter(name => data.statuses[name] !== undefined)
            .map(name => [name, data.statuses[name]]);


        updateChart(
            statusChart,
            statusEntries.map(item => item[0]),
            statusEntries.map(item => item[1]),

            statusEntries.map(item => ({
                Detected: chartColors.orange,
                Investigating: chartColors.blue,
                Blocked: chartColors.green,
                Contained: chartColors.purple
            })[item[0]])
        );


        renderIncidents(data.incidents);

    } catch (error) {

        console.error("Historical analytics error:", error);

        document.getElementById("incidentRows").innerHTML = `
            <tr>
                <td colspan="5" class="empty-state">
                    Unable to load historical incidents.
                </td>
            </tr>
        `;
    }
}


// -----------------------------------------
// LIVE MONITORING CONTROLS
// -----------------------------------------

async function startMonitoring() {

    const button = document.getElementById("startMonitor");

    button.disabled = true;

    try {

        const response = await fetch(
            `${MONITOR_API}/start`,
            {
                method: "POST"
            }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Unable to start monitoring");
        }

        await refreshLiveMonitoring();

    } catch (error) {

        console.error(error);

        alert("Monitoring error: " + error.message);

    } finally {

        button.disabled = false;
    }
}


async function stopMonitoring() {

    const button = document.getElementById("stopMonitor");

    button.disabled = true;

    try {

        const response = await fetch(
            `${MONITOR_API}/stop`,
            {
                method: "POST"
            }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Unable to stop monitoring");
        }

        await refreshLiveMonitoring();

    } catch (error) {

        console.error(error);

        alert("Monitoring error: " + error.message);

    } finally {

        button.disabled = false;
    }
}


// -----------------------------------------
// MONITORING STATUS
// -----------------------------------------

async function loadMonitoringStatus() {

    try {

        const response = await fetch(
            `${MONITOR_API}/status`
        );

        if (!response.ok) {
            throw new Error("Status API unavailable");
        }

        const data = await response.json();

        const running = data.running;

        document.getElementById("packetCount").textContent =
            Number(data.packet_count).toLocaleString();


        document.getElementById("interfaceName").textContent =
            data.interface;


        document.getElementById("captureStatus").textContent =
            running ? "Running" : "Stopped";


        document.getElementById("monitorBadge").textContent =
            running ? "LIVE" : "STOPPED";


        document.getElementById("monitorBadge").className =
            running ? "live-indicator active" : "live-indicator";


        document.getElementById("startMonitor").disabled =
            running;

        document.getElementById("stopMonitor").disabled =
            !running;


        document.getElementById("systemStatus").textContent =
            "Dashboard Online";

    } catch (error) {

        console.error("Monitoring status error:", error);

        document.getElementById("systemStatus").textContent =
            "API Connection Error";
    }
}


// -----------------------------------------
// LIVE TRAFFIC
// -----------------------------------------

async function loadLiveTraffic() {

    try {

        const response = await fetch(
            `${MONITOR_API}/traffic`
        );

        if (!response.ok) {
            throw new Error("Traffic API unavailable");
        }

        const data = await response.json();

        const tbody = document.getElementById("trafficRows");

        const traffic = data.traffic || [];


        document.getElementById("trafficCount").textContent =
            data.total + " packets";


        if (!traffic.length) {

            tbody.innerHTML = `
                <tr>
                    <td colspan="6" class="empty-state">
                        No traffic captured yet.
                    </td>
                </tr>
            `;

            return;
        }


        tbody.innerHTML = traffic.map(packet => `

            <tr>

                <td>${escapeHTML(packet.timestamp)}</td>

                <td>${escapeHTML(packet.source_ip)}</td>

                <td>${escapeHTML(packet.destination_ip)}</td>

                <td>
                    <span class="protocol-badge">
                        ${escapeHTML(packet.protocol)}
                    </span>
                </td>

                <td>${escapeHTML(packet.destination_port)}</td>

                <td>${escapeHTML(packet.packet_size)} bytes</td>

            </tr>

        `).join("");

    } catch (error) {

        console.error("Traffic loading error:", error);
    }
}


// -----------------------------------------
// SECURITY ALERTS
// -----------------------------------------

async function loadSecurityAlerts() {

    try {

        const response = await fetch(
            `${MONITOR_API}/alerts`
        );

        if (!response.ok) {
            throw new Error("Alerts API unavailable");
        }

        const data = await response.json();

        const alerts = data.alerts || [];

        const tbody = document.getElementById("alertRows");


        document.getElementById("alertCount").textContent =
            alerts.length + " alerts";

        document.getElementById("liveAlertCount").textContent =
            alerts.length;


        if (!alerts.length) {

            tbody.innerHTML = `
                <tr>
                    <td colspan="5" class="empty-state">
                        No security alerts generated yet.
                    </td>
                </tr>
            `;

            return;
        }


        tbody.innerHTML = alerts.map(alert => {

            const severity = escapeHTML(alert.severity);

            return `

                <tr>

                    <td>${escapeHTML(alert.timestamp)}</td>

                    <td>${escapeHTML(alert.type)}</td>

                    <td>${escapeHTML(alert.source_ip)}</td>

                    <td>
                        <span class="badge ${severityClass(severity)}">
                            ${severity}
                        </span>
                    </td>

                    <td>${escapeHTML(alert.description)}</td>

                </tr>

            `;

        }).join("");

    } catch (error) {

        console.error("Alert loading error:", error);
    }
}


// -----------------------------------------
// REFRESH LIVE DATA
// -----------------------------------------

async function refreshLiveMonitoring() {

    await Promise.all([
        loadMonitoringStatus(),
        loadLiveTraffic(),
        loadSecurityAlerts()
    ]);
}


// -----------------------------------------
// INITIALIZATION
// -----------------------------------------

document.addEventListener("DOMContentLoaded", () => {

    createCharts();


    document.getElementById("startMonitor")
        .addEventListener("click", startMonitoring);


    document.getElementById("stopMonitor")
        .addEventListener("click", stopMonitoring);


    [
        "severityFilter",
        "statusFilter",
        "threatFilter"
    ].forEach(id => {

        document.getElementById(id)
            .addEventListener("change", loadDashboard);

    });


    document.getElementById("searchInput")
        .addEventListener("input", loadDashboard);


    document.getElementById("resetFilters")
        .addEventListener("click", () => {

            document.getElementById("severityFilter").value = "";
            document.getElementById("statusFilter").value = "";
            document.getElementById("threatFilter").value = "";
            document.getElementById("searchInput").value = "";

            loadDashboard();
        });


    loadDashboard();

    refreshLiveMonitoring();


    refreshTimer = setInterval(() => {

        refreshLiveMonitoring();

    }, 2000);

});