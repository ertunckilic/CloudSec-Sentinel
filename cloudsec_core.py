import json

import boto3
from botocore.exceptions import ClientError

# Veritabanı modülümüzü içe aktarıyoruz
import database_manager as db


def get_sentinel_session(role_arn, external_id, session_name="SentinelScanSession"):
    sts_client = boto3.client("sts")
    try:
        response = sts_client.assume_role(
            RoleArn=role_arn, RoleSessionName=session_name, ExternalId=external_id
        )
        credentials = response["Credentials"]
        return boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
        )
    except ClientError as e:
        print(f"[X] Baglanti hatasi: {e}")
        return None


def check_s3_public_access(s3_client, bucket_name, conn, scan_id):
    try:
        response = s3_client.get_public_access_block(Bucket=bucket_name)
        config = response["PublicAccessBlockConfiguration"]

        if (
            config.get("BlockPublicAcls")
            and config.get("IgnorePublicAcls")
            and config.get("BlockPublicPolicy")
            and config.get("RestrictPublicBuckets")
        ):
            return True, "[+] GUVENLI (Kalkan Aktif)"
        else:
            # Zafiyet bulundu, veritabanına kaydet
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO security_findings (scan_id, bucket_name, issue_details) VALUES (?, ?, ?)",
                (
                    scan_id,
                    bucket_name,
                    "KALKAN DELINIK (Public Access Block devre disi)",
                ),
            )
            conn.commit()
            return False, "[-] RISKLI (Kalkan Devre Disi)"

    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO security_findings (scan_id, bucket_name, issue_details) VALUES (?, ?, ?)",
                (
                    scan_id,
                    bucket_name,
                    "KALKAN YOK (Public Access Block hic kurulmamis)",
                ),
            )
            conn.commit()
            return False, "[!] RISKLI (Kalkan Hic Kurulmamis)"
        return None, f"[X] Hata: {e.response['Error']['Code']}"


def check_s3_data_leak(s3_client, bucket_name, conn, scan_id):
    try:
        policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
        policy = json.loads(policy_response["Policy"])

        for statement in policy.get("Statement", []):
            if statement.get("Effect") == "Allow":
                principal = statement.get("Principal", "")
                if principal == "*" or (
                    isinstance(principal, dict) and principal.get("AWS") == "*"
                ):
                    action = statement.get("Action", "")
                    if (
                        "s3:GetObject" in action
                        or action == "s3:*"
                        or (isinstance(action, list) and "s3:GetObject" in action)
                    ):
                        cursor = conn.cursor()
                        cursor.execute(
                            "INSERT INTO security_findings (scan_id, bucket_name, issue_details) VALUES (?, ?, ?)",
                            (
                                scan_id,
                                bucket_name,
                                "KRITIK SIZINTI: Veriler internete acik (Public Read)",
                            ),
                        )
                        conn.commit()

                        return "[!!!] KRITIK SIZINTI: Veriler internete acik!"

        return "[i] Kalkan delik ama dogrudan sızıntı politikası yok."

    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
            return "[i] Kalkan delik ama kova politikasi bos."
        return f"[X] Politika okunamadi: {e.response['Error']['Code']}"


def scan_ebs_waste(session, conn, scan_id, region="eu-central-1"):
    print(f"\n--- {region.upper()} BOLGESI MALIYET ISRAFI TARAMASI ---")
    ec2 = session.client("ec2", region_name=region)
    total_wasted_gb = 0
    wasted_cost_usd = 0.0

    try:
        volumes = ec2.describe_volumes(
            Filters=[{"Name": "status", "Values": ["available"]}]
        )

        if not volumes["Volumes"]:
            print("  [+] Bosta bekleyen israf diski bulunmadi.")
            return

        for vol in volumes["Volumes"]:
            vol_id = vol["VolumeId"]
            size = vol["Size"]
            cost = size * 0.08
            total_wasted_gb += size
            wasted_cost_usd += cost

            # İsrafı veritabanına kaydet
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO cost_findings (scan_id, resource_type, resource_id, monthly_waste_usd) VALUES (?, ?, ?, ?)",
                (scan_id, "EBS_VOLUME", vol_id, cost),
            )
            conn.commit()

            print(f"  [-] Israf: {vol_id} - {size} GB")

        print("-" * 50)
        print(
            f"  [$$$] TOPLAM AYLIK ISRAF: {total_wasted_gb} GB -> Yaklasik ${wasted_cost_usd:.2f} / Ay"
        )

    except ClientError as e:
        print(f"[X] EBS diskleri okunamadi: {e.response['Error']['Code']}")


def scan_eip_waste(session, conn, scan_id, region="eu-central-1"):
    print(f"\n--- {region.upper()} BOLGESI ELASTIC IP ISRAFI TARAMASI ---")
    ec2 = session.client("ec2", region_name=region)
    wasted_ips = 0

    try:
        addresses = ec2.describe_addresses()

        if not addresses["Addresses"]:
            print("  [+] Hesaba bagli Elastic IP bulunmadi.")
            return

        for eip in addresses["Addresses"]:
            if "InstanceId" not in eip:
                ip_address = eip["PublicIp"]
                wasted_ips += 1
                estimated_cost = 3.60

                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO cost_findings (scan_id, resource_type, resource_id, monthly_waste_usd) VALUES (?, ?, ?, ?)",
                    (scan_id, "ELASTIC_IP", ip_address, estimated_cost),
                )
                conn.commit()

                print(f"  [-] Israf: Bosta bekleyen IP adresi ({ip_address})")

        if wasted_ips > 0:
            print("-" * 50)
            total_estimated_cost = wasted_ips * 3.60
            print(
                f"  [$$$] TOPLAM AYLIK ELASTIC IP ISRAFI: {wasted_ips} Adet -> Yaklasik ${total_estimated_cost:.2f} / Ay"
            )
        else:
            print(
                "  [+] Bosta bekleyen Elastic IP bulunmadi (Tum IP'ler aktif kullanimda)."
            )

    except ClientError as e:
        print(f"[X] Elastic IP'ler okunamadi: {e.response['Error']['Code']}")


if __name__ == "__main__":
    MUSTERI_ROL_ARN = "arn:aws:iam::054037138082:role/CloudSecSentinelRole"
    GIZLI_ID = "Sentinel-Super-Secret-ID-2026"
    MUSTERI_ADI = "Test_Sirketi_A"

    # Kendi ARN adresini buraya tekrar yaz!

    # 1. Veritabanını başlat ve yeni oturum aç
    conn = db.init_db()
    current_scan_id = db.start_new_scan(conn, MUSTERI_ADI)

    print(f"\n=== CLOUDSEC SENTINEL BASLATILDI (Oturum ID: {current_scan_id}) ===\n")

    session = get_sentinel_session(MUSTERI_ROL_ARN, GIZLI_ID)

    if session:
        # S3 Taraması
        s3 = session.client("s3")
        try:
            kovalar = s3.list_buckets()
            print("--- S3 GUVENLIK TARAMASI ---")

            for bucket in kovalar["Buckets"]:
                bucket_name = bucket["Name"]
                print(f"[*] Analiz: {bucket_name}")

                is_secure, block_status = check_s3_public_access(
                    s3, bucket_name, conn, current_scan_id
                )
                print(f"  |-- {block_status}")

                if is_secure is False:
                    leak_status = check_s3_data_leak(
                        s3, bucket_name, conn, current_scan_id
                    )
                    print(f"  |-- {leak_status}")

        except ClientError as e:
            print(f"[X] Kovalar listelenemedi: {e}")

        # Maliyet Taramaları
        scan_ebs_waste(session, conn, current_scan_id, region="eu-central-1")
        scan_eip_waste(session, conn, current_scan_id, region="eu-central-1")

        print("\n=== TARAMA TAMAMLANDI VE VERITABANINA KAYDEDILDI ===")

    conn.close()
