# iCYLENS

iCYLENS is an experimental cybersecurity analysis platform. The current phase
provides a typed FastAPI backend with versioned routes, validated contracts,
and centralized environment configuration.

Phase 01 baseline: `0.1.0`, technically accepted on 2026-10-25 after an
independent audit. See the [vision](docs/PROJECT_VISION.md),
[architecture](docs/ARCHITECTURE.md), [API contracts](docs/API_CONTRACTS.md),
[audit report](docs/PHASE_01_AUDIT_REPORT.md), and
[acceptance record](docs/PHASE_01_ACCEPTANCE.md).

## Backend prerequisites

- Python 3.12 or 3.13
- PowerShell commands below are run from `C:\icylens\apps\api`

## Local setup

Clone or otherwise obtain the repository, then enter the backend directory:

```powershell
git clone <repository-url> icylens
Set-Location .\icylens\apps\api
```

When the repository already exists at the documented location:

```powershell
Set-Location C:\icylens\apps\api
```

Create the environment and install the declared development dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
Copy-Item .env.example .env
```

The `dev` extra installs the runtime dependencies plus pytest, pytest-cov,
HTTPX, Ruff, and mypy.
The project currently uses compatible version ranges rather than a lockfile;
strict deployment locking can be added when the deployment workflow is chosen.

`.env` contains local configuration and is ignored by Git. `.env.example` is a
safe, versioned template. The application also works without a `.env` file.

## Configuration

All external variables use the `ICYLENS_` prefix:

| Variable | Default | Purpose |
|---|---|---|
| `ICYLENS_APP_NAME` | `iCYLENS API` | Application and health-service name |
| `ICYLENS_APP_VERSION` | `0.1.0` | API and health-service version |
| `ICYLENS_APP_ENV` | `development` | `development`, `testing`, or `production` |
| `ICYLENS_DEBUG` | `false` | FastAPI debug mode; forbidden in production |
| `ICYLENS_API_V1_PREFIX` | `/api/v1` | Prefix for v1 routes |
| `ICYLENS_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL` |

Operating-system environment variables take precedence over values in `.env`,
which take precedence over code defaults. Unknown `.env` values are ignored so
unrelated local variables do not prevent startup. Settings are cached once per
process; tests clear that cache when changing environment variables.

## Run the API

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Swagger is available at <http://127.0.0.1:8000/docs> and the health endpoint at
<http://127.0.0.1:8000/api/v1/health/>. Interactive documentation remains
available in all environments for this foundation phase. Production rejects
debug mode, and the default command binds only to the local interface.

## Testing and quality gates

The suite uses pytest markers to make its intent explicit:

- `unit`: isolated settings, schema, and utility behavior.
- `integration`: assembled FastAPI behavior through `TestClient`.
- `contract`: request validation and response/OpenAPI contracts.
- `security`: repository and environment-configuration safety checks.

All tests override every supported setting before importing the application,
use controlled settings, and require no internet connection, database, or
listening network port. A developer's local `.env` cannot change test outcomes,
and tests never modify it. Run the complete suite with:

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

Branch coverage is measured over `app` and must remain at or above 85%. HTML
and XML reports are written to `htmlcov/` and `coverage.xml`:

```powershell
.\.venv\Scripts\python.exe -m pytest --cov=app --cov-branch --cov-report=term-missing --cov-report=html --cov-report=xml
```

Ruff enforces imports and selected defect-oriented lint rules and verifies
canonical formatting. Mypy checks `app` and `scripts` in strict mode:

```powershell
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe -m pip check
```

The unified gate runs each mandatory check with the active Python interpreter
and returns nonzero if any check fails:

```powershell
.\.venv\Scripts\python.exe scripts\quality_gate.py
```

A failure identifies its gate in the output. Fix the underlying lint,
formatting, typing, test, coverage, or dependency issue and rerun the command.
Coverage indicates executed code, not correctness; assertions and realistic
failure-path tests remain essential even when coverage is high.

Dependency vulnerability scanning is not part of the mandatory offline gate.
The Phase 01 audit ran `pip-audit` in a disposable clean virtual environment
and found no known vulnerabilities in the declared dependency closure. Add an
audit step to CI when network and advisory-database access are available.
