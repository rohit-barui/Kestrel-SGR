from .celery_app import app


@app.task(bind=True)
def run_skill(self, skill_name: str, inputs: dict):
    """Execute a named skill function via Celery.

    The skill is resolved from the global registry at call time so workers
    always use the latest definition.
    """
    from .engine import _SKILL_REGISTRY
    func = _SKILL_REGISTRY.get(skill_name)
    if func is None:
        raise ValueError(f"Unknown skill: {skill_name}")
    return func(inputs)
