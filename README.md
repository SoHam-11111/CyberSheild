\# CyberShield

\### A Big Data Analytics Platform for Cyber Threat Intelligence and Network Intrusion Detection



\## Overview



CyberShield is a cybersecurity analytics platform that combines historical security incident analysis with live network traffic monitoring.



The system uses Big Data technologies to store, process and analyse security incident records, while a Python-based monitoring module captures network packets and identifies potentially suspicious activity.



\## Key Features



\- Historical security incident analysis.

\- Distributed data storage using Hadoop HDFS.

\- Data import using Apache Sqoop.

\- Analytical queries using Apache Hive and Impala.

\- Live network packet capture using Scapy.

\- Rule-based detection of potential DDoS attacks, port scans and repeated connections.

\- Security alerts and live traffic monitoring.

\- Flask-based web dashboard.



\## Technology Stack



| Technology | Purpose |

|---|---|

| Python | Backend development and detection logic |

| MySQL | Historical incident database |

| Apache Hadoop HDFS | Distributed data storage |

| Apache Sqoop | Data transfer from MySQL to HDFS |

| Apache Hive | Data analysis and aggregation |

| Apache Impala | Interactive analytical queries |

| Scapy | Live network packet capture |

| Flask | Web application and APIs |

| HTML, CSS, JavaScript | Dashboard interface |



\## System Architecture



The project consists of two main pipelines.



\### 1. Historical Data Analytics Pipeline



MySQL -> Sqoop -> HDFS -> Hive / Impala -> Flask Dashboard



The historical pipeline processes 800 security incident records and performs threat-wise and severity-wise analysis.



\### 2. Live Network Monitoring Pipeline



Network Interface -> Scapy -> Packet Processing -> Detection Engine -> Security Alerts -> Flask Dashboard



The detection engine uses predefined thresholds to identify potentially suspicious network activity.



\## Detection Rules



| Detection Type | Rule |

|---|---|

| Possible DDoS | More than 100 packets from the same source-destination pair within 10 seconds |

| Possible Port Scan | More than 15 distinct destination ports from the same source within 10 seconds |

| Repeated Connections | More than 30 initial TCP SYN packets to the same destination and port within 10 seconds |



These rules are heuristic-based and may generate false positives. Alerts indicate potentially suspicious activity, not confirmed attacks.



\## Testing



\- Historical database connectivity.

\- Sqoop data import into HDFS.

\- Hive and Impala analytical queries.

\- Flask dashboard functionality.

\- Live network packet capture.

\- Live traffic API.

\- Detection engine functionality.

\- Security alerts API and dashboard.



\## Limitations



\- The historical dataset contains 800 synthetic demonstration records.

\- Detection is based on predefined rules rather than a trained machine learning model.

\- Live monitoring depends on the selected network interface.

\- Heuristic detection can produce false positives.



\## Disclaimer



CyberShield is an academic project developed for educational and demonstration purposes. Network monitoring should only be performed on authorised networks.



\## Author



Developed as an academic Big Data Analytics project.

