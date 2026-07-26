import os

from fastapi.testclient import TestClient

from api import app

# Testler icerisinde hata almamak icin sahte ortam degiskenlerimizi tanimliyoruz
os.environ["ADMIN_USER"] = "admin"
os.environ["ADMIN_PASS"] = "Sentinel2026!"  # nosec B105

client = TestClient(app)


def test_guvenlik_duvari_calisiyor_mu():
    response = client.get("/")
    assert response.status_code == 401


def test_yetkili_kullanici_girisi():
    response = client.get("/", auth=("admin", "Sentinel2026!"))
    assert response.status_code == 200
    assert "CloudSec Sentinel" in response.text


def test_raporlama_motoru():
    response = client.get("/api/v1/generate-report", auth=("admin", "Sentinel2026!"))
    assert response.status_code == 200
    assert response.json()["status"] == "success"
