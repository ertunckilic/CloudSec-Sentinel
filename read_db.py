import sqlite3


def show_all_findings(db_name="sentinel_core.db"):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    print("\n=== CLOUDSEC SENTINEL VERITABANI (HAFIZA) DOKUMU ===")

    cursor.execute("SELECT scan_id, scan_date, customer_name FROM scans")
    scans = cursor.fetchall()

    if not scans:
        print("[i] Henuz kaydedilmis bir tarama yok.")
        return

    for scan in scans:
        scan_id, scan_date, customer_name = scan
        print(
            f"\n[Oturum ID: {scan_id}] | Tarih: {scan_date} | Musteri: {customer_name}"
        )

        cursor.execute(
            "SELECT bucket_name, issue_details FROM security_findings WHERE scan_id=?",
            (scan_id,),
        )
        sec_findings = cursor.fetchall()

        if sec_findings:
            print("  [!] Guvenlik Zafiyetleri:")
            for finding in sec_findings:
                print(f"      - Kova: {finding[0]}\n      - Detay: {finding[1]}")
        else:
            print("  [+] Guvenlik acigi bulunmadi.")

        cursor.execute(
            "SELECT resource_type, resource_id, monthly_waste_usd FROM cost_findings WHERE scan_id=?",
            (scan_id,),
        )
        cost_findings = cursor.fetchall()

        if cost_findings:
            print("  [$$$] Maliyet Israf Bulgulari:")
            for finding in cost_findings:
                print(f"      - {finding[0]} [{finding[1]}]: ${finding[2]:.2f} / Ay")
        else:
            print("  [+] Maliyet israfi bulunmadi.")

    conn.close()
    print("\n==================================================\n")


if __name__ == "__main__":
    show_all_findings()
