import sqlite3
from datetime import datetime, timezone


def init_db(db_name="sentinel_core.db"):
    """Veritabanını ve gerekli tabloları yoksa oluşturur."""
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    # 1. Tarama Oturumları (Hangi müşteri, ne zaman tarandı?)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_date TEXT,
        customer_name TEXT
    )
    """)

    # 2. Güvenlik Bulguları
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        bucket_name TEXT,
        issue_details TEXT,
        FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
    )
    """)

    # 3. Maliyet İsrafı Bulguları
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cost_findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        resource_type TEXT,
        resource_id TEXT,
        monthly_waste_usd REAL,
        FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
    )
    """)

    conn.commit()
    return conn


def start_new_scan(conn, customer_name):
    """Yeni bir tarama oturumu başlatır ve ID'sini döndürür."""
    cursor = conn.cursor()
    # Zaman damgasina UTC saat dilimi standardini ekledik (Ruff DTZ005 cozumu)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        "INSERT INTO scans (scan_date, customer_name) VALUES (?, ?)",
        (now, customer_name),
    )
    conn.commit()
    return cursor.lastrowid


if __name__ == "__main__":
    print("\n--- CLOUDSEC SENTINEL VERITABANI KURULUMU ---")

    # Veritabanını başlat
    baglanti = init_db()
    print("[+] sentinel_core.db dosyasi basariyla olusturuldu ve tablolar hazirlandi.")

    # Test için sahte bir tarama başlat
    yeni_tarama_id = start_new_scan(baglanti, "EphemerSec_Test_Musterisi")
    print(f"[+] Yeni tarama oturumu baslatildi. (Oturum ID: {yeni_tarama_id})")

    print("--- KURULUM TAMAMLANDI ---\n")
