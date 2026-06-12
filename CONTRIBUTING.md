# Contributing Guidelines

Thank you for your interest in improving APCS! Follow these steps to ensure a smooth contribution process.

## 1. Fork the Repository
- Click the **Fork** button on GitHub to create your own copy.
- Clone your fork locally:
  ```powershell
  git clone https://github.com/<your‑username>/Kestrel-SGR.git
  cd Kestrel-SGR
  ```

## 2. Create a Feature Branch
```powershell
git checkout -b feature/<short‑description>
```
Use a descriptive name (e.g., `feature/add-qr-scanner`).

## 3. Set Up the Development Environment
```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```
If you add new third‑party libraries, update `requirements.txt` accordingly.

## 4. Code Style
- Follow **PEP 8** (use `flake8` locally if you like).
- Add type hints where possible.
- Keep functions small and focused; avoid adding unrelated utilities.
- Update documentation (`docs/` files) for any public API change.

## 5. Testing
- Add unit tests under the `tests/` directory.
- Ensure all tests pass locally:
  ```powershell
  python -m unittest discover -s tests
  ```
- Aim for at least **80 %** overall coverage.

## 6. Commit Messages
Use the conventional format:
```
<type>(<scope>): <short summary>

<optional longer description>

Closes #<issue-number>
```
Examples: `feat(perception): add QR code scanner`, `fix(gateway): correct rollback order`.

## 7. Pull Request
- Push your branch to your fork:
  ```powershell
  git push origin feature/<short‑description>
  ```
- Open a PR against the upstream `main` branch.
- Link any related issue(s) in the PR description.
- The CI will run the test suite automatically.

## 8. Review Process
- One of the maintainers will review the PR.
- Address any feedback by pushing additional commits to the same branch.
- When approved, the maintainer will merge the PR.

---

Happy hacking!