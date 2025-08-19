# DNS Automation API

This project provides a **FastAPI-based automation tool** for managing DNS records with **BIND** using **TSIG-authenticated dynamic updates**.  
It supports adding, deleting, and verifying records in real-time, including integration with **PowerDNS** (MariaDB backend) and forwarder validation.

---

## Features
- Add, delete, and update DNS records (A, PTR, CNAME, MX, NS, etc.).
- Zone existence and record verification via **AXFR**.
- Forwarder validation with retries and automatic reloads.
- Secure **TSIG authentication** for DNS updates.
- Modular verification logic via `checker.py`.
- Supports both master-slave and forwarder DNS setups.

---

## Architecture

```
+----------------+ +----------------+ +----------------+
| Master DNS | | Slave DNS | | Forwarder |
| 10.60.110.227 | <---> | 10.60.110.228 | <--- | 10.60.110.229 |
| (BIND + TSIG) | | (BIND Slave) | | Queries Slave |
+----------------+ +----------------+ +----------------+
^ ^ ^
| | |
| +----------+----------+ |
| | DNS Automation API | |
+-------------| (FastAPI + Python) |---------------+
+---------------------+
```
---

## Project Structure

## Project Structure

```text
.
├── main.py                 # FastAPI application entrypoint (API endpoints)
├── bind_manager/
│   ├── checker.py          # DNS record verification logic (zone/AXFR/forwarder checks)
│   └── record_manager.py   # DNS record management operations (add, update, delete)
├── config/
│   └── logging_config.py   # Logging configuration for the project
├── requirements.txt        # Python dependencies
└── README.md               # Project documentation

```
---

## Prerequisites
- **Python** 3.10+
- **BIND 9** with dynamic update enabled.
- TSIG key configured in both BIND and the application.

---

## Installation
```bash
git clone https://netops.devpod.ir/shirin.shahsavani/bindautomationapi.git
cd dns-automation
pip install -r requirements.txt
