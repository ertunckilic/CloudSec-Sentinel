# Hafif ve güvenli resmi Python imajini kullaniyoruz
FROM python:3.12-slim

# Konteyner icindeki calisma dizinini ayarla
WORKDIR /app

# Sistem guncellemeleri (Kutuphanelerin hatasiz calismasi icin)
RUN apt-get update && apt-get install -y \
    build-essential \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Once kutuphane listesini kopyala (Docker onbellek optimizasyonu icin)
COPY requirements.txt .

# Kutuphaneleri kur
RUN pip install --no-cache-dir -r requirements.txt

# Tum proje dosyalarini konteynere kopyala
COPY . .

# FastAPI'nin calisacagi portu disa ac
EXPOSE 8000

# API motorunu baslat
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
