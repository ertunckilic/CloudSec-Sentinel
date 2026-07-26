import logging
import os
import secrets
import sqlite3
import sys

from dotenv import load_dotenv
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

import cloudsec_core as core
import database_manager as db
import remediation_generator as tf_gen
import report_generator as report

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler("sentinel_api.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)

TARGET_REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-1")

tags_metadata = [
    {"name": "System", "description": "Altyapi ve saglik kontrolu uclari."},
    {"name": "Dashboard", "description": "Kullanici arayuzu ve istatistik paneli."},
    {
        "name": "Security Scans",
        "description": "Otonom bulut guvenlik ve israf analiz motoru.",
    },
    {
        "name": "Remediation & Reports",
        "description": "Otomatik Terraform ve HTML rapor uretimi.",
    },
]

app = FastAPI(
    title="CloudSec Sentinel Enterprise API",
    description="""
    **Otonom Bulut Güvenlik ve Maliyet Optimizasyonu Motoru.**
    Bu API, AWS ortamlarindaki S3 sizintilarini ve EBS/EIP israflarini otonom olarak tespit eder,
    ardindan aninda Terraform cozumleri ve yonetici raporlari uretir.
    """,
    version="1.0.0",
    contact={
        "name": "Ertunc",
        "url": "https://github.com/ertunckilic/CloudSec-Sentinel",
    },
    license_info={
        "name": "MIT License",
    },
    openapi_tags=tags_metadata,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

templates = Jinja2Templates(directory="templates")
security = HTTPBasic()


def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):  # noqa: B008
    correct_username = secrets.compare_digest(
        credentials.username, os.getenv("ADMIN_USER", "admin")
    )
    correct_password = secrets.compare_digest(
        credentials.password, os.getenv("ADMIN_PASS", "Sentinel2026!")
    )
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Hatali kullanici adi veya sifre",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


class ScanRequest(BaseModel):
    customer_name: str
    role_arn: str
    external_id: str = "Sentinel-Super-Secret-ID-2026"


def perform_background_scan(customer_name: str, role_arn: str, external_id: str):
    try:
        conn = db.init_db()
        scan_id = db.start_new_scan(conn, customer_name)

        session = core.get_sentinel_session(role_arn, external_id)
        if not session:
            logger.error(
                f"[{scan_id}] AWS STS Baglantisi basarisiz. Musteri: {customer_name}"
            )
            conn.close()
            return

        s3 = session.client("s3")
        try:
            kovalar = s3.list_buckets()
            for bucket in kovalar["Buckets"]:
                bucket_name = bucket["Name"]
                is_secure, _ = core.check_s3_public_access(
                    s3, bucket_name, conn, scan_id
                )
                if is_secure is False:
                    core.check_s3_data_leak(s3, bucket_name, conn, scan_id)
        except Exception as e:  # noqa: BLE001
            logger.error(f"[{scan_id}] Kritik S3 Taramasi Hatasi: {e}")

        core.scan_ebs_waste(session, conn, scan_id, region=TARGET_REGION)
        core.scan_eip_waste(session, conn, scan_id, region=TARGET_REGION)

        conn.close()
        logger.info(
            f"[{scan_id}] {customer_name} taramasi {TARGET_REGION} bolgesinde basariyla tamamlandi."
        )
    except Exception as e:  # noqa: BLE001
        logger.error(f"Arka plan gorevi cokerken yakalandi: {e}")


@app.get("/health", tags=["System"])
def health_check():
    return {"status": "healthy", "version": "1.0.0", "engine": "CloudSec Sentinel"}


@app.get("/", tags=["Dashboard"])
def read_dashboard(request: Request, username: str = Depends(verify_credentials)):
    conn = sqlite3.connect("sentinel_core.db")
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM scans")
    total_scans = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM security_findings")
    total_vulns = cursor.fetchone()[0]

    cursor.execute("SELECT SUM(monthly_waste_usd) FROM cost_findings")
    waste_result = cursor.fetchone()[0]
    total_waste = waste_result if waste_result else 0.0

    cursor.execute(
        "SELECT scan_id, scan_date, customer_name FROM scans ORDER BY scan_id DESC LIMIT 5"
    )
    recent_scans = cursor.fetchall()

    conn.close()

    stats = {
        "total_scans": total_scans,
        "total_vulns": total_vulns,
        "total_waste": total_waste,
    }

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"request": request, "stats": stats, "recent_scans": recent_scans},
    )


@app.post("/api/v1/scan", tags=["Security Scans"])
def start_cloud_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    username: str = Depends(verify_credentials),
):
    background_tasks.add_task(
        perform_background_scan,
        request.customer_name,
        request.role_arn,
        request.external_id,
    )
    return {
        "status": "success",
        "message": f"{request.customer_name} icin derin analiz arka planda baslatildi. Sonuclar kisa sure icinde panele yansiyacaktir.",
    }


@app.get("/api/v1/generate-report", tags=["Remediation & Reports"])
def generate_html(username: str = Depends(verify_credentials)):
    report.generate_html_report()
    return {"status": "success", "message": "HTML raporu olusturuldu"}


@app.get("/api/v1/generate-remediation", tags=["Remediation & Reports"])
def generate_tf(username: str = Depends(verify_credentials)):
    tf_gen.generate_terraform_remediation()
    return {"status": "success", "message": "Terraform duzeltme scripti uretildi"}
