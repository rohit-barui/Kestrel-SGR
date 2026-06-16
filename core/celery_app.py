from celery import Celery

app = Celery(
    "apcs",
    broker="memory://",
    backend="cache+memory://",
)

# Default config – eager mode allows tests without a broker
app.conf.update(
    task_always_eager=True,
    task_eager_propagates=True,
    task_store_eager_result=True,
)

if __name__ == "__main__":
    app.start()
