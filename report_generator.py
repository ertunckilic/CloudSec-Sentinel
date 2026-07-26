import os
import sqlite3

from jinja2 import Template


def generate_html_report(db_name="sentinel_core.db", output_file="rapor_onizleme.html"):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    # En son yapılan taramayı veritabanından çek
    cursor.execute(
        "SELECT scan_id, scan_date, customer_name FROM scans ORDER BY scan_id DESC LIMIT 1"
    )
    scan = cursor.fetchone()

    if not scan:
        print("[X] Veritabaninda tarama bulunamadi.")
        return

    scan_id, scan_date, customer_name = scan

    # Zafiyetleri ve maliyet verilerini çek
    cursor.execute(
        "SELECT bucket_name, issue_details FROM security_findings WHERE scan_id=?",
        (scan_id,),
    )
    sec_findings = cursor.fetchall()

    cursor.execute(
        "SELECT resource_type, resource_id, monthly_waste_usd FROM cost_findings WHERE scan_id=?",
        (scan_id,),
    )
    cost_findings = cursor.fetchall()

    total_waste = sum(item[2] for item in cost_findings)

    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>CloudSec Sentinel Raporu</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #1e293b; line-height: 1.6; background-color: #f1f5f9; padding: 20px; }
            .container { max-width: 800px; margin: auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); }
            .header { background-color: #0f172a; color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; margin: -40px -40px 20px -40px; }
            .header h1 { margin: 0; font-size: 28px; letter-spacing: 2px; }
            .header p { margin: 5px 0 0 0; color: #94a3b8; }
            .summary-box { border: 1px solid #e2e8f0; padding: 20px; margin: 20px 0; border-radius: 6px; background-color: #f8fafc; }
            .summary-title { font-size: 18px; font-weight: bold; margin-bottom: 15px; border-bottom: 2px solid #cbd5e1; padding-bottom: 8px; color: #334155; }
            .alert-red { color: #dc2626; font-weight: bold; }
            .alert-green { color: #16a34a; font-weight: bold; }
            table { width: 100%; border-collapse: collapse; margin-top: 10px; }
            th, td { border: 1px solid #cbd5e1; padding: 12px; text-align: left; }
            th { background-color: #e2e8f0; color: #475569; }
            .footer { margin-top: 40px; font-size: 13px; text-align: center; color: #94a3b8; border-top: 1px solid #e2e8f0; padding-top: 20px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>CLOUDSEC SENTINEL</h1>
                <p>Otomatik Bulut Altyapı ve Güvenlik Denetim Raporu</p>
            </div>

            <div class="summary-box">
                <div class="summary-title">Özet Bilgiler</div>
                <p><strong>Müşteri:</strong> {{ customer_name }}</p>
                <p><strong>Tarama Tarihi:</strong> {{ scan_date }}</p>
                <p><strong>Tespit Edilen Güvenlik Açığı:</strong> <span class="{% if sec_count > 0 %}alert-red{% else %}alert-green{% endif %}">{{ sec_count }} Adet</span></p>
                <p><strong>Aylık Bulut İsrafı:</strong> <span class="{% if total_waste > 0 %}alert-red{% else %}alert-green{% endif %}">${{ "%.2f"|format(total_waste) }}</span></p>
            </div>

            <div class="summary-box">
                <div class="summary-title">Güvenlik Zafiyet Detayları (S3)</div>
                {% if sec_findings %}
                <table>
                    <tr><th>Etkilenen Kaynak (Kova)</th><th>Risk Detayı</th></tr>
                    {% for finding in sec_findings %}
                    <tr>
                        <td>{{ finding[0] }}</td>
                        <td class="alert-red">{{ finding[1] }}</td>
                    </tr>
                    {% endfor %}
                </table>
                {% else %}
                <p class="alert-green">Tebrikler, herhangi bir güvenlik zafiyeti bulunamadı.</p>
                {% endif %}
            </div>

            <div class="summary-box">
                <div class="summary-title">Maliyet Optimizasyonu (İsraf)</div>
                {% if cost_findings %}
                <table>
                    <tr><th>Kaynak Tipi</th><th>Kaynak ID</th><th>Aylık İsraf</th></tr>
                    {% for finding in cost_findings %}
                    <tr>
                        <td>{{ finding[0] }}</td>
                        <td>{{ finding[1] }}</td>
                        <td class="alert-red">${{ "%.2f"|format(finding[2]) }}</td>
                    </tr>
                    {% endfor %}
                </table>
                {% else %}
                <p class="alert-green">Gereksiz bulut israfı tespit edilmedi. Sistem optimize çalışıyor.</p>
                {% endif %}
            </div>

            <div class="footer">
                Bu rapor <strong>CloudSec Sentinel</strong> algoritması tarafından sıfır müdahale ile otomatik olarak oluşturulmuştur. <br> Gizli ve Müşteriye Özeldir.
            </div>
        </div>
    </body>
    </html>
    """

    template = Template(html_template)
    rendered_html = template.render(
        customer_name=customer_name,
        scan_date=scan_date,
        sec_count=len(sec_findings),
        total_waste=total_waste,
        sec_findings=sec_findings,
        cost_findings=cost_findings,
    )

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(rendered_html)

    print(f"\n[+] HARIKA! Rapor basariyla '{output_file}' adinda kaydedildi.")
    print(
        f"    -> PyCharm üzerinden veya bilgisayarindan {os.path.abspath(output_file)} dosyasina cift tiklayarak tarayicinda acabilirsin."
    )
    print(
        "    -> PDF olarak kaydetmek icin tarayicida 'Ctrl + P' (Yazdir) basip 'PDF Olarak Kaydet' secmen yeterlidir!"
    )


if __name__ == "__main__":
    generate_html_report()
