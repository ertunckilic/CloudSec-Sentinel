.PHONY: install run test scan build up down

install:
	pip install -r requirements.txt

run:
	uvicorn api:app --reload

test:
	pytest

scan:
	bandit -r . -x .venv,venv -s B101

build:
	docker build -t cloudsec-sentinel .

up:
	docker run -d -p 8000:8000 --name sentinel cloudsec-sentinel

down:
	docker stop sentinel && docker rm sentinel
