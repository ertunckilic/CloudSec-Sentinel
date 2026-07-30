from fastapi.testclient import TestClient
from api import app
import database_manager as db

# CI/CD ortaminda testler baslamadan once tablolari otonom olarak yaratir
try:
    conn = db.init_db()
    if conn:
        conn.close()
except Exception:
    pass

client = TestClient(app)


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200


def test_yetkili_kullanici_girisi():
    response = client.get("/", auth=("admin", "Sentinel2026!"))
    assert response.status_code == 200


def test_raporlama_motoru():
    response = client.get("/api/v1/generate-report", auth=("admin", "Sentinel2026!"))
    assert response.status_code == 200
