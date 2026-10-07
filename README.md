# BindAuto — DNS Automation API

**BindAuto** is a FastAPI-based DNS automation service for managing DNS records on BIND name servers through authenticated dynamic DNS updates.

The service provides a centralized API for creating, updating, and deleting DNS records on a BIND master server, while validating zone and record state and verifying synchronization with configured forwarders.

---

## Overview

BindAuto automates common DNS management operations that would otherwise require manual changes on BIND servers.

The service:

1. Validates the requested DNS operation.
2. Validates the target zone and record.
3. Authenticates the request.
4. Sends a TSIG-authenticated DNS UPDATE to the BIND master.
5. Applies the zone changes using BIND freeze/thaw operations where required.
6. Verifies that configured forwarders have received the change.
7. Reloads a forwarder when synchronization is not detected.
8. Retries forwarder verification when necessary.
9. Rolls back changes when synchronization fails in operations that support rollback.

Each operation is also assigned a unique `operation_id` for tracking and logging.

---

## Features

* Create DNS records
* Update DNS records
* Delete DNS records
* Support for multiple DNS record types
* TSIG-authenticated dynamic DNS updates
* Zone existence validation
* Record existence validation
* Forwarder synchronization verification
* Automatic forwarder reload
* Retry mechanism for forwarder synchronization
* Rollback when forwarder synchronization fails
* Automatic PTR creation for A records
* BIND zone freeze/thaw handling
* Request authentication
* Request serialization using an application lock
* Structured application logging
* Operation IDs for tracing DNS operations

---

## Supported Record Types

BindAuto currently supports the following record types:

| Record Type | Supported |
| ----------- | --------- |
| A           | Yes       |
| AAAA        | Yes       |
| PTR         | Yes       |
| CNAME       | Yes       |
| MX          | Yes       |
| NS          | Yes       |
| TXT         | Yes       |

The record type is provided as part of the API endpoint.

Example:

```text
POST /add/A/
POST /add/MX/
POST /update/CNAME/
POST /delete/TXT/
```

---

## Architecture

The general request flow is:

```text
                         ┌──────────────────────┐
                         │       Client         │
                         └──────────┬───────────┘
                                    │
                                    │ HTTP / REST API
                                    ▼
                         ┌──────────────────────┐
                         │      BindAuto        │
                         │      FastAPI         │
                         └──────────┬───────────┘
                                    │
                 ┌──────────────────┼──────────────────┐
                 │                  │                  │
                 ▼                  ▼                  ▼
        ┌────────────────┐  ┌────────────────┐  ┌──────────────┐
        │ Authentication │  │    Checker     │  │    Record    │
        │ & Validation   │  │                │  │   Manager    │
        └────────────────┘  └────────────────┘  └──────┬───────┘
                                                       │
                                                       │ DNS UPDATE
                                                       ▼
                                              ┌──────────────────┐
                                              │   BIND Master    │
                                              │   + TSIG Key     │
                                              └────────┬─────────┘
                                                       │
                                                       │ Zone Transfer
                                                       ▼
                                              ┌──────────────────┐
                                              │    Forwarders    │
                                              └──────────────────┘
```

### Main Components

#### FastAPI Application

`main.py` exposes the HTTP API and is responsible for:

* Receiving API requests
* Validating request data
* Authenticating clients
* Resolving the requested DNS location
* Generating an `operation_id`
* Calling the appropriate record-management function

The API uses an `asyncio.Lock` to prevent multiple DNS operations from being processed concurrently. If another operation is already running, the API returns HTTP `429`.

#### Checker

`bind_manager/checker.py` contains validation and verification logic, including:

* DNS record type validation
* Zone existence checks
* Record existence checks
* Forwarder verification
* DNS synchronization checks

#### Record Manager

`bind_manager/record_manager.py` contains the main DNS operation logic:

* Add
* Update
* Delete
* Record-type-specific behavior
* DNS UPDATE generation
* Forwarder verification
* Forwarder reload
* Rollback handling

DNS updates are sent to the BIND master using `dnspython` and TSIG authentication.

---

## Project Structure

```text
.
├── main.py
│   └── FastAPI application and API endpoints
│
├── bind_manager/
│   ├── checker.py
│   │   └── DNS validation and verification logic
│   │
│   └── record_manager.py
│       └── DNS record management and synchronization logic
│
├── config/
│   ├── settings.py
│   │   └── Application configuration
│   │
│   └── logging_config.py
│       └── Logging configuration
│
├── run.py
│   └── BIND zone freeze/thaw operations
│
├── requirements.txt
│   └── Python dependencies
│
└── README.md
    └── Project documentation
```

---

# DNS Operation Flow

## Add Record

A typical add operation follows this flow:

```text
Client
  │
  ▼
POST /add/{record_type}/
  │
  ├── Authenticate request
  │
  ├── Validate location
  │
  ├── Validate record type
  │
  ├── Check zone
  │
  ├── Check whether record already exists
  │
  ▼
BIND Master
  │
  ├── DNS UPDATE
  │
  └── Freeze / Thaw
  │
  ▼
Forwarder Verification
  │
  ├── Already synchronized → Success
  │
  ├── Not synchronized → Reload
  │
  └── Still not synchronized → Rollback / Error
```

For A records, BindAuto can optionally create the corresponding PTR record automatically when `AUTO_CREATE_PTR_FOR_A_RECORD` is enabled.

---

## Update Record

The update endpoint receives both the existing value and the new value.

```text
POST /update/{record_type}/
```

The service:

1. Validates the record type.
2. Checks that the zone exists.
3. Verifies the existing record.
4. Replaces the old value with the new value.
5. Applies the zone changes.
6. Verifies synchronization with forwarders.

The update flow is implemented through `update_record_progress()` and the record manager.

---

## Delete Record

```text
POST /delete/{record_type}/
```

The delete operation:

1. Authenticates the request.
2. Validates the zone and record type.
3. Verifies that the target record exists.
4. Removes the record from the BIND master.
5. Verifies the result on configured forwarders.

---

# Forwarder Synchronization

One of the main responsibilities of BindAuto is ensuring that a DNS change made on the master is eventually visible through configured forwarders.

After a record is modified on the master, BindAuto checks the corresponding forwarder.

If the forwarder has not synchronized the change:

```text
Master updated
      │
      ▼
Forwarder check
      │
      ├── Synced ──────────────► Success
      │
      └── Not synced
              │
              ▼
        Trigger reload
              │
              ▼
        Check status
              │
              ▼
        Verify DNS record
              │
       ┌──────┴──────┐
       │             │
    Success        Failure
       │             │
       ▼             ▼
    Continue       Retry /
                  Rollback
```

The forwarder reload mechanism calls the forwarder's reload API and then checks its reload status with retry/backoff behavior.

---

# Rollback

BindAuto includes rollback handling for synchronization failures in the add flow.

If a record has been successfully created on the master but the forwarder cannot synchronize after the configured retry attempts, the service removes the newly created record from the master.

The failed operation returns an HTTP `502` response indicating that the forwarder was not synchronized and that the operation was rolled back.

This prevents the system from silently reporting a successful operation while the DNS infrastructure remains inconsistent.

---

# Authentication

API requests are authenticated using a token supplied through the request header.

The service also distinguishes between regular API authentication and master-specific authentication for operations such as zone apply/freeze/thaw.

DNS updates themselves use a configured TSIG key:

```text
KEY_NAME
KEY_SECRET
KEY_ALGORITHM
```

The TSIG credentials are used when constructing the DNS UPDATE request sent to the BIND master.

> **Security note:** TSIG secrets and application authentication credentials should never be committed to the repository.

---

# Configuration

Application settings are loaded through the project's configuration module.

Typical configuration includes:

| Configuration                  | Description                                                |
| ------------------------------ | ---------------------------------------------------------- |
| `KEY_NAME`                     | TSIG key name                                              |
| `KEY_SECRET`                   | TSIG secret                                                |
| `KEY_ALGORITHM`                | TSIG algorithm                                             |
| `MAX_RETRY`                    | Maximum synchronization retry count                        |
| `AUTO_CREATE_PTR_FOR_A_RECORD` | Automatically create PTR for A records                     |
| `fernet_key`                   | Key used for internal token encryption                     |
| `client_ip`                    | Client/API identity used for internal authentication       |
| `locations_ip`                 | Mapping of DNS locations to master and forwarder addresses |

The exact configuration values are environment-specific and should be provided through the deployment environment rather than hard-coded in the repository.

---

# Prerequisites

Before running BindAuto, make sure the following components are available:

* Python 3.10+
* BIND 9
* A BIND master configured for dynamic DNS updates
* Configured TSIG key
* Configured DNS zones
* Network connectivity between BindAuto and the BIND master
* Network connectivity between BindAuto and configured forwarders
* Required Python dependencies from `requirements.txt`

---

# Installation

Clone the repository:

```bash
git clone https://netops.devpod.ir/shirin.shahsavani/bindautomationapi.git
```

Enter the project directory:

```bash
cd bindautomationapi
```

Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

On Windows:

```powershell
python -m venv venv
venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# Running the Application

The FastAPI application runs on port `8000` by default.

Run directly with Python:

```bash
python main.py
```

Or run with Uvicorn:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

The application exposes its API through:

```text
http://<server-ip>:8000
```

FastAPI's interactive documentation is available at:

```text
http://<server-ip>:8000/docs
```

---

# API Reference

## Add Record

```http
POST /add/{record_type}/
```

Example:

```http
POST /add/A/
```

Request body:

```json
{
  "zone": "example.com",
  "record_name": "server01",
  "record_value": "192.0.2.10",
  "ttl": 300,
  "priority": 10,
  "location": "TEST"
}
```

---

## Update Record

```http
POST /update/{record_type}/
```

Example:

```http
POST /update/A/
```

Request body:

```json
{
  "zone": "example.com",
  "record_name": "server01",
  "record_value": "192.0.2.10",
  "second_value": "192.0.2.20",
  "ttl": 300,
  "priority": 10,
  "location": "TEST"
}
```

`record_value` represents the current value and `second_value` represents the new value.

---

## Delete Record

```http
POST /delete/{record_type}/
```

Example:

```http
POST /delete/A/
```

Request body:

```json
{
  "zone": "example.com",
  "record_name": "server01",
  "record_value": "192.0.2.20",
  "ttl": 300,
  "priority": 10,
  "location": "TEST"
}
```

---

## Apply Zone Changes

```http
POST /{zone}/apply/
```

Request body:

```json
{
  "location": "TEST"
}
```

This endpoint validates the zone and performs the configured BIND freeze/thaw operation.

---

# Request Validation

BindAuto performs validation before modifying DNS data.

Examples include:

### Location validation

The requested location must exist in the configured location mapping.

### Record type validation

Only supported record types are accepted.

### Zone validation

The requested zone must exist on the target DNS master.

### Record existence validation

Depending on the operation, BindAuto verifies whether the requested record already exists or does not exist before continuing.

### Record value validation

Specific record types may have additional validation.

For example, A record values are validated as IPv4 addresses before the DNS update is sent.

---

# Error Handling

BindAuto uses HTTP status codes to report operation failures.

Common responses include:

| Status Code | Meaning                                    |
| ----------: | ------------------------------------------ |
|       `400` | Invalid request or record value            |
|       `403` | Authentication or DNS operation failure    |
|       `404` | Zone/location/record not found             |
|       `409` | Record already exists                      |
|       `429` | Another DNS operation is currently running |
|       `502` | Forwarder synchronization failed           |
|       `503` | Forwarder is unreachable                   |

The service returns additional information in the response body to help identify the failed operation.

---

# Concurrency Control

DNS operations are protected by an application-level `asyncio.Lock`.

Only one add, update, or delete operation can be processed at a time.

If the service is already processing another operation, a new request receives:

```http
429 Too Many Requests
```

with:

```json
{
  "detail": "The server is busy. Please try again later."
}
```

This prevents simultaneous operations from interfering with each other's DNS state and rollback tracking.

---

# Logging

BindAuto uses Python's logging framework.

Logging is initialized through:

```text
config/logging_config.py
```

Logs are used to track:

* Incoming requests
* DNS operations
* Record changes
* Forwarder verification
* Reload operations
* Retry attempts
* Rollback operations
* Errors and exceptions
* Operation IDs

Example log flow:

```text
Add request
     │
     ▼
DNS validation
     │
     ▼
Master update
     │
     ▼
Forwarder verification
     │
     ├── Success
     │
     └── Retry / Reload / Rollback
```

---

# Operational Considerations

## BIND Configuration

The BIND master must be configured to accept dynamic updates from BindAuto using the configured TSIG key.

The application does not replace BIND configuration; it acts as an automation layer on top of the existing DNS infrastructure.

## Network Connectivity

BindAuto must be able to communicate with:

* BIND master
* Configured forwarders
* Forwarder management APIs

## TSIG Synchronization

The TSIG key name, secret, and algorithm configured in BindAuto must match the corresponding BIND configuration.

## Forwarder Availability

Forwarder synchronization is part of the operation flow. A DNS change may be rolled back if a forwarder cannot successfully synchronize within the configured retry policy.

---

# Example End-to-End Operation

Suppose the client wants to create:

```text
server01.example.com → 192.0.2.10
```

The request is:

```http
POST /add/A/
```

BindAuto performs:

```text
1. Authenticate client
        ↓
2. Validate location
        ↓
3. Validate record type
        ↓
4. Check zone
        ↓
5. Check existing record
        ↓
6. Validate IPv4 address
        ↓
7. Send TSIG-authenticated DNS UPDATE
        ↓
8. Apply BIND zone changes
        ↓
9. Verify forwarder
        ↓
10. Reload forwarder if required
        ↓
11. Verify synchronization again
        ↓
12. Return success
```

If automatic PTR creation is enabled, BindAuto also creates the corresponding PTR record.

---

# Troubleshooting

## DNS UPDATE fails

Check:

* BIND master connectivity
* Zone configuration
* TSIG key name
* TSIG secret
* TSIG algorithm
* BIND dynamic update permissions

## Forwarder is not synchronized

Check:

* Network connectivity to the forwarder
* Forwarder DNS service
* Forwarder reload API
* Zone transfer configuration
* Retry configuration
* BIND logs on the master and forwarder

## HTTP 429

Another DNS operation is currently running.

Wait for the current operation to finish and retry the request.

## HTTP 502

The requested DNS operation could not be successfully synchronized with the configured forwarder.

Check the application logs and forwarder status.

## HTTP 503

The service could not reach the target forwarder.

Verify network connectivity and that the forwarder's API is available.

---

# Development

The project separates API handling from DNS business logic:

```text
main.py
   │
   ├── Request handling
   ├── Authentication
   └── Input validation
          │
          ▼
bind_manager/
   │
   ├── checker.py
   │      └── Validation & verification
   │
   └── record_manager.py
          └── DNS operations
```

This separation allows DNS logic to be developed and tested independently from the HTTP API layer.

---

# Summary

BindAuto provides an API-driven automation layer for BIND DNS management.

Its main responsibilities are:

```text
             ┌──────────────────────────┐
             │       BindAuto           │
             ├──────────────────────────┤
             │ API                      │
             │ Authentication           │
             │ Validation               │
             │ DNS UPDATE               │
             │ Zone Management          │
             │ Forwarder Verification   │
             │ Automatic Reload         │
             │ Retry                    │
             │ Rollback                 │
             │ Logging                  │
             └──────────────────────────┘
```

The goal is to make DNS changes **consistent, validated, traceable, and automated**, while minimizing the need for direct manual modification of BIND configuration or zone data.
