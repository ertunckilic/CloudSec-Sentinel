import os
import sqlite3


def generate_terraform_remediation(
    db_name="sentinel_core.db", output_file="remediation_fix.tf"
):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    # En son taramayı al
    cursor.execute("SELECT scan_id FROM scans ORDER BY scan_id DESC LIMIT 1")
    scan = cursor.fetchone()

    if not scan:
        print("[X] Veritabaninda tarama bulunamadi.")
        return

    scan_id = scan[0]

    # Güvenlik zafiyetlerini (S3) çek
    cursor.execute(
        "SELECT bucket_name, issue_details FROM security_findings WHERE scan_id=?",
        (scan_id,),
    )
    sec_findings = cursor.fetchall()

    if not sec_findings:
        print("[+] Duzeltilecek guvenlik zafiyeti yok. Sistem tamamen guvenli.")
        return

    # Terraform Dosyası Başlangıcı
    tf_code = """# ==============================================================================
# CLOUDSEC SENTINEL - OTOMATIK GUVENLIK DUZELTME (REMEDIATION) KODU
# ==============================================================================
# Bu Terraform scripti, sistemde tespit edilen aciklari otomatik kapatmak icin
# CloudSec Sentinel motoru tarafindan ozel olarak uretilmistir.
# Calistirmak icin terminalde:
# 1. terraform init
# 2. terraform apply
# ==============================================================================

provider "aws" {
  region = "eu-central-1"
}
\n"""

    fix_count = 0
    for finding in sec_findings:
        bucket_name = finding[0]
        issue = finding[1]

        # Kalkan delikse, kalkanı kapatan Terraform bloğunu dinamik olarak üret
        if "KALKAN" in issue:
            # Terraform kaynak isimlerinde tire (-) yerine alt çizgi (_) kullanılması önerilir
            resource_name = bucket_name.replace("-", "_")

            tf_code += f"""
# Zafiyet Kapatiliyor: {bucket_name} (Public Access Block Devreye Aliniyor)
resource "aws_s3_bucket_public_access_block" "fix_{resource_name}" {{
  bucket = "{bucket_name}"

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}}
\n"""
            fix_count += 1

    if fix_count > 0:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(tf_code)
        print(
            f"\n[+] MUKEMMEL! {fix_count} adet zafiyeti otomatik onaran Terraform kodu uretildi."
        )
        print(f"    -> Duzeltme Dosyasi: {os.path.abspath(output_file)}")
        print(
            "    -> Musteri bu Terraform dosyasini kullanarak saniyeler icinde aciklarini kapatabilir."
        )
    else:
        print(
            "\n[i] Mevcut zafiyetler icin otomatik Terraform duzeltmesi (henuz) gerekmiyor."
        )


if __name__ == "__main__":
    generate_terraform_remediation()
