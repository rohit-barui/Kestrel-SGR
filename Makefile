.PHONY: build run stop clean test lint format coverage ci

build:
	docker compose build

run:
	docker compose up -d

stop:
	docker compose down

logs:
	docker compose logs -f

test:
	python -m unittest discover -s tests -v

lint:
	ruff check .

format:
	ruff format .

coverage:
	coverage run -m unittest discover -s tests -v
	coverage report
	coverage html

ci: lint test coverage

clean:
	docker compose down -v
	rm -rf __pycache__ core/__pycache__ skills/__pycache__ tests/__pycache__
