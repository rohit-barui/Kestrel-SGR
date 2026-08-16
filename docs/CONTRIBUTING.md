# Contributing

## Workflow

1. **Fork** the repository
2. **Create a branch**: `feature/<short-description>`
3. **Make changes** following PEP-8 and existing code conventions
4. **Write tests** for any new or modified functionality
5. **Run the test suite**: `python -m pytest tests/ -q`
6. **Check coverage**: `python -m pytest --cov=core --cov=skills --cov=server --cov-report=term`
7. **Update documentation** for any public API changes
8. **Commit** with clear, descriptive messages
9. **Open a PR** against `main`

## Branch Naming

```
feature/<short-description>
```

Examples:
- `feature/ml-model-update`
- `feature/siem-connector-azure`
- `fix/replay-decrypt-error`

## Code Style

- **Python**: PEP-8, line length 120, double quotes
- **JavaScript**: Standard JS conventions, camelCase
- **CSS**: BEM-like naming, CSS custom properties for theming
- **Rego**: Follow existing policy patterns

## Commit Messages

Use conventional commit format:
```
type: short description

- Bullet point details
- Reference issues with #issue-number
```

Types: `feat`, `fix`, `chore`, `docs`, `test`, `refactor`, `ci`

## Pull Request Checklist

Before opening a PR, ensure:
- [ ] Branch is up to date with `main`
- [ ] `git status` is clean
- [ ] `pytest --cov` passes with >=95% overall and >=99% per-file coverage
- [ ] No TODOs or `# pragma: no cover` left unintentionally
- [ ] Documentation updated for any public API changes
- [ ] Changelog updated with a concise entry

## Testing Requirements

- All new code must have corresponding unit tests
- Tests must not depend on external services (mock DNS, WHOIS, APIs)
- Run `python ci/check_coverage.py` to verify coverage thresholds
- Coverage is enforced in CI — PRs that reduce coverage will be blocked

## Documentation

Update the following when making changes:
- `CHANGELOG.md` — add entry under `[Unreleased]`
- `docs/CORE.md` — if modifying core runtime
- `docs/SKILLS.md` — if adding/changing skills
- `docs/WEB_UI.md` — if modifying the dashboard
- `docs/POLICIES.md` — if changing Rego policies
- `README.md` — if adding major features or API endpoints