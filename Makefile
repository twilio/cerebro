all: docker-build docker-test

local-install:
	virtualenv venv --python=python3 && sleep 5 && source venv/bin/activate && pip install -r requirements.txt

local-test:
	source venv/bin/activate && pytest tests/

local-run:
	source venv/bin/activate && python cerebro.py

docker-build:
	docker-compose build cerebro

docker-test:
	docker-compose run cerebro pytest tests/

docker-run:
	docker-compose run cerebro python cerebro.py
