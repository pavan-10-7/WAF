# WAF Testing Environment

This directory contains the testing environment and validation scripts for the Web Application Firewall (WAF) project.

## 1. Overview

The testing environment is designed to validate the WAF against three attack categories:

- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Path Traversal

It also includes benign request tests to help evaluate whether legitimate traffic is handled correctly.

## 2. Architecture

The local testing setup uses:

- **DVWA:** Vulnerable web application used as the test target.
- **Docker:** Runs the DVWA container.
- **Python:** Executes attack simulations and benign request tests.
- **Requests:** Sends HTTP requests to DVWA and, where configured, the WAF proxy.

Expected architecture:

Attacker / Test Scripts → WAF Proxy (Port 8080) → DVWA (Port 8081)

The direct DVWA tests establish baseline application behaviour. Tests through the WAF proxy are required to evaluate detection and blocking effectiveness.

## 3. Directory Structure

```text
testing/
├── attacks/
│   ├── __init__.py
│   ├── common.py
│   ├── sqli.py
│   ├── xss.py
│   ├── traversal.py
│   └── benign.py
├── data/
├── reports/
├── tests/
├── docker-compose.yml
├── requirements.txt
└── README.md
```

## 4. Prerequisites

- Python 3.10 or later
- Docker Desktop
- Git
- Internet connection for initial dependency installation and Docker image retrieval

## 5. Setup

From the repository root:

```bash
cd testing
python -m venv .venv
source .venv/Scripts/activate
pip install -r requirements.txt
```

For Windows PowerShell, activate the environment using:

```powershell
.venv\Scripts\Activate.ps1
```

## 6. Start DVWA

From the `testing/` directory:

```bash
docker compose up -d
```

DVWA is expected to be available at:

```text
http://localhost:8081
```

Open DVWA in your browser, log in with the configured local credentials, and initialize the database if required.

Set the DVWA security level to **Low** for the baseline tests.

## 7. Run Individual Tests

Run the scripts from the `testing/` directory:

```bash
python -m attacks.sqli
python -m attacks.xss
python -m attacks.traversal
python -m attacks.benign
```

The scripts authenticate with DVWA and execute the corresponding test requests.

## 8. Test Interpretation

- **SQL Injection:** Sends a SQL injection test payload to the DVWA SQL Injection module.
- **XSS:** Checks whether a harmless test marker is reflected in the response.
- **Path Traversal:** Checks whether a traversal request can retrieve a local test file such as `/etc/passwd` inside the DVWA container.
- **Benign Requests:** Sends normal requests to the application to establish baseline behaviour.

A successful HTTP response alone does not establish that an attack succeeded. Each test uses its own response-based validation.

## 9. WAF Integration Testing

Direct requests to DVWA are baseline tests and do not demonstrate WAF protection.

For WAF validation, configure the test scripts to send requests through the proxy at:

```text
http://localhost:8080
```

The expected behaviour is:

- Malicious requests should be detected and blocked.
- Legitimate requests should be allowed.
- Detection results should follow the agreed detector response contract.
- Security events should be recorded in the agreed JSONL event format.

End-to-end WAF validation must be performed after the proxy and detector integration is available.

## 10. Stop the Environment

From the `testing/` directory:

```bash
docker compose down
```

To remove the containers and associated volumes:

```bash
docker compose down -v
```

**Note:** The `-v` option removes associated Docker volumes and may delete local application data.