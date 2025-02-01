🛡️ Process Anomaly Detector
Process Anomaly Detector is a lightweight Go-based monitoring tool designed to detect suspicious process behavior in Unix-like systems. It continuously analyzes process trees, CPU and memory usage, network connections, and parent-child relationships to identify potential security threats or system anomalies.

🔍 Features
Parent-Child Relationship Analysis – Detects unusual process hierarchies (e.g., nginx -> bash).\n
CPU & Memory Monitoring – Flags processes consuming excessive system resources.\n
Network Connection Inspection – Alerts on suspicious listening ports and outbound connections.
Automated Alerts – Sends notifications to a monitoring system via webhooks.
Process Termination – Can automatically kill suspicious processes.
Logging System – Stores detected anomalies for later analysis.

This tool is ideal for system administrators, security engineers, and DevOps professionals looking for a simple yet effective process monitoring solution. 🚀
