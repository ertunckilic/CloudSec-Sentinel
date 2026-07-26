# CloudSec Sentinel

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Security Scan](https://img.shields.io/badge/security-bandit-green)
![Python Version](https://img.shields.io/badge/python-3.12-blue)
![License](https://img.shields.io/badge/license-MIT-blue)

**Enterprise-Grade Autonomous Cloud Security & Cost Optimization Engine**

CloudSec Sentinel is a highly advanced, zero-touch SaaS platform designed to autonomously detect critical security vulnerabilities and infrastructure waste across AWS environments. Upon detection, it instantly generates deployable Terraform (`.tf`) remediation scripts and executive-ready reports.

## Key Features

*   **Autonomous S3 Auditing:** Deep scanning of bucket policies, Public Access Blocks, and potential data leak vectors.
*   **Cost Optimization Engine:** Identifies unattached EBS volumes and idle Elastic IPs, instantly calculating monthly infrastructure waste.
*   **Infrastructure as Code (IaC) Remediation:** Dynamically generates precise `.tf` code to instantly patch discovered vulnerabilities.
*   **Asynchronous Processing:** Heavy cloud scans are securely executed in the background via FastAPI background tasks, ensuring zero UI blocking.
*   **Enterprise Security:** Core API and Dashboard are shielded by strictly implemented HTTP Basic Authentication and .env secret management.

## Architecture

1.  **Frontend:** Modern, dark-mode dashboard powered by Tailwind CSS, Chart.js, and Jinja2 templates.
2.  **Backend:** FastAPI engine with SQLite database for session and scan history logging.
3.  **Cloud Integration:** Boto3 (AWS SDK) with secure STS role assumption.
4.  **DevSecOps Pipeline:** Fully Dockerized, verified by Pytest, and scanned by Bandit (SAST), integrated into GitHub Actions CI/CD.

## Quick Start (Docker)

The fastest way to deploy CloudSec Sentinel in an isolated environment:

```bash
# Clone the repository
git clone [https://github.com/YOUR_USERNAME/CloudSec-Sentinel.git](https://github.com/YOUR_USERNAME/CloudSec-Sentinel.git)
cd CloudSec-Sentinel

# Setup Environment Variables
cp .env.example .env
# Edit .env with your desired admin credentials

# Build and Run via Docker
docker build -t cloudsec-sentinel .
docker run -d -p 8000:8000 --env-file .env cloudsec-sentinel
```

Navigate to `http://localhost:8000` and login with your configured credentials.

## Manual Development Setup

If you prefer running directly on your machine via Makefile:

```bash
make install
make run
```

## Running Tests & Security Scans

```bash
# Run Unit Tests
make test

# Run SAST Security Scan
make scan
```
