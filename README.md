# SOC Simulator – Host & Network IDS Platform

## Overview

SOC Simulator is a standalone Host and Network Intrusion Detection Platform designed to simulate the operational workflow of a modern Security Operations Center (SOC). The platform integrates real-time log collection, threat detection, incident visualization, alert correlation, and forensic preservation into a centralized interactive dashboard environment.

The project was developed to demonstrate how enterprise-level monitoring and detection systems operate by combining Host-Based Intrusion Detection System (HIDS) and Network-Based Intrusion Detection System (NIDS) functionalities within a unified dashboard architecture. The system continuously monitors host activities, network behavior, Windows security events, registry modifications, scheduled tasks, firewall activity, WMI operations, process executions, and multiple other telemetry sources to identify suspicious or malicious activities.

The platform performs large-scale rule-based detection against collected logs and generates categorized alerts based on severity levels such as Critical, High, Medium, and Low. Generated incidents are automatically grouped, visualized, and displayed through a dynamic SOC dashboard that provides analysts with real-time situational awareness.

Unlike traditional static academic IDS projects, this platform focuses heavily on practical SOC simulation by reproducing the workflow followed by real-world analysts during incident monitoring, alert triaging, threat visualization, and forensic investigation.

---

# Project Objectives

The primary objectives of this project are:

* To simulate the functionality of a real-world SOC environment.
* To integrate both HIDS and NIDS capabilities into a centralized platform.
* To collect and analyze logs from multiple host and network telemetry sources.
* To generate real-time alerts using rule-based detection mechanisms.
* To visualize threats through interactive dashboard components and severity distributions.
* To provide forensic preservation functionality for detected incidents.
* To demonstrate enterprise-style alert management and incident monitoring workflows.
* To create a portable standalone cybersecurity monitoring platform capable of operating in isolated environments.

---

# Key Features

## Centralized SOC Dashboard

The dashboard acts as the primary monitoring interface for the entire platform. It provides:

* Real-time alert monitoring
* Severity distribution visualization
* Threat category analytics
* Alert queue management
* System health monitoring
* Memory and storage utilization tracking
* Host and network activity overview
* Dynamic chart-based incident visualization

---

## Host-Based Intrusion Detection System (HIDS)

The HIDS component continuously monitors host-level activities including:

* Windows Event Logs
* Sysmon Logs
* Registry Modifications
* PowerShell Activity
* Scheduled Tasks
* Process Creation Events
* Driver Loading
* Authentication Events
* Security Policy Changes
* Persistence Mechanisms
* Privilege Escalation Attempts
* Credential Access Activities

The collected events are analyzed against extensive detection rules to identify suspicious behavior patterns.

---

## Network-Based Intrusion Detection System (NIDS)

The NIDS module monitors and analyzes network-related telemetry including:

* Active Network Connections
* DNS Activity
* Firewall Logs
* Suspicious Remote Connections
* Beaconing Patterns
* Command and Control Traffic
* Reverse Shell Connections
* Port Scanning Attempts
* Lateral Movement Indicators
* Proxy and VPN Manipulations
* Malicious IP Communication

The platform identifies anomalous network behavior and correlates it with host-level activities for improved threat visibility.

---

# Detection Engine

The platform contains a large-scale rule-based detection engine responsible for analyzing collected telemetry against predefined attack patterns and behavioral indicators.

The engine supports:

* Threshold-based detection
* Pattern matching
* Multi-stage intrusion correlation
* Persistence detection
* Malware activity detection
* Privilege escalation monitoring
* Defense evasion detection
* Credential theft indicators
* Lateral movement detection
* Ransomware behavior monitoring
* Fileless malware detection
* Command execution analysis
* Registry abuse detection
* LOLBin activity detection

Generated alerts are automatically categorized based on severity and stored for visualization and forensic analysis.

---

# Alert Management System

The alert management system organizes incidents into structured categories and displays them through the dashboard interface.

Features include:

* Severity-based grouping
* Real-time alert queue updates
* Timestamp-based incident tracking
* Alert filtering and sorting
* Incident prioritization
* Threat category distribution
* Historical alert analysis
* Dashboard synchronization

---

# Forensics Module

The platform includes a forensic preservation capability that allows generated alerts and evidence to be saved for future investigation and reporting purposes.

The forensic workflow includes:

* Alert snapshot preservation
* Incident export functionality
* Evidence storage
* Historical log retention
* Investigation-oriented data organization

---

# System Architecture

The project follows a modular architecture where different components operate independently while communicating through centralized APIs and shared data storage.

The architecture consists of:

* Dashboard Frontend
* API Backend
* Detection Engine
* Log Collection Modules
* Alert Management System
* Database Layer
* Forensics Storage Module
* Visualization Engine

This modular design improves maintainability, scalability, and feature extensibility.

---

# Log Sources Monitored

The platform supports monitoring of multiple telemetry sources including:

* Sysmon Logs
* Windows Security Logs
* Firewall Logs
* Defender Logs
* Registry Events
* WMI Events
* DNS Logs
* Scheduled Task Logs
* Process Activity
* Network Connections
* Driver Events
* Authentication Logs
* Service Events
* PowerShell Execution Logs

---

# Visualization and Analytics

The dashboard provides multiple visual components for SOC monitoring including:

* Severity Distribution Charts
* Threat Category Visualization
* Alert Counters
* Incident Queues
* Resource Utilization Indicators
* Timeline-Based Monitoring
* Real-Time Dashboard Updates

The visual analytics layer enables analysts to quickly identify abnormal activity patterns and prioritize threats.

---

# Standalone Deployment Capability

The platform is designed to operate as a standalone executable-based application for isolated or offline demonstration environments. Dependencies can be packaged locally to support deployment without requiring internet connectivity.

This allows the project to be demonstrated in secure or air-gapped virtual machine environments while maintaining complete dashboard functionality.

---

# Educational and Research Value

This project demonstrates practical cybersecurity monitoring concepts including:

* SOC Operations Workflow
* Intrusion Detection Techniques
* Host Monitoring
* Network Monitoring
* Threat Detection
* Alert Correlation
* Security Visualization
* Incident Management
* Forensic Preservation
* Threat Hunting Concepts

The platform can be used for academic demonstrations, cybersecurity learning, SOC workflow simulation, and IDS research experimentation.

---

# Conclusion

SOC Simulator is a comprehensive cybersecurity monitoring platform that combines host-based and network-based intrusion detection functionalities into a unified SOC environment. The system demonstrates how modern security monitoring infrastructures operate by integrating telemetry collection, threat detection, visualization, alert management, and forensic preservation into a centralized dashboard-driven architecture.

The project emphasizes real-world SOC simulation, modular system design, large-scale detection handling, and analyst-oriented visualization to provide an effective demonstration of modern cybersecurity monitoring workflows.
