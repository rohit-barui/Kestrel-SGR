.PHONY: build run stop clean test

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

clean:
	docker compose down -v
	rm -rf __pycache__ core/__pycache__ skills/__pycache__ tests/__pycache__
