package builtin

// popularPyPI is the typosquat reference corpus for PyPI (PEP 503 normalized).
// PyPI has a long history of squats on exactly these names — the ecosystem's
// flat, unscoped namespace makes it easier than npm's.
var popularPyPI = []string{
	"requests", "urllib3", "boto3", "botocore", "setuptools", "six", "certifi",
	"idna", "charset-normalizer", "python-dateutil", "numpy", "pandas", "scipy",
	"matplotlib", "pyyaml", "jinja2", "markupsafe", "click", "flask", "django",
	"fastapi", "starlette", "pydantic", "uvicorn", "gunicorn", "werkzeug",
	"sqlalchemy", "alembic", "psycopg2", "psycopg2-binary", "pymysql", "redis",
	"celery", "kombu", "pytest", "pytest-cov", "tox", "mock", "coverage",
	"attrs", "packaging", "pyparsing", "wheel", "pip", "virtualenv", "colorama",
	"cryptography", "pyopenssl", "cffi", "pycparser", "bcrypt", "paramiko",
	"pillow", "opencv-python", "scikit-learn", "tensorflow", "torch", "keras",
	"transformers", "tokenizers", "huggingface-hub", "openai", "anthropic",
	"langchain", "tiktoken", "beautifulsoup4", "lxml", "soupsieve", "html5lib",
	"scrapy", "selenium", "httpx", "aiohttp", "anyio", "sniffio", "h11",
	"protobuf", "grpcio", "google-api-core", "google-auth", "awscli",
	"typing-extensions", "importlib-metadata", "zipp", "filelock", "fsspec",
	"tqdm", "rich", "typer", "loguru", "structlog", "sentry-sdk", "prometheus-client",
	"jsonschema", "marshmallow", "python-dotenv", "environs", "pytz", "tzdata",
	"docker", "kubernetes", "ansible", "jmespath", "s3transfer", "smmap",
	"gitpython", "pygments", "docutils", "sphinx", "mkdocs", "black", "flake8",
	"mypy", "isort", "pylint", "ruff", "poetry", "pipenv", "twine", "build",
}

var popularPyPISet = func() map[string]struct{} {
	m := make(map[string]struct{}, len(popularPyPI))
	for _, n := range popularPyPI {
		m[n] = struct{}{}
	}
	return m
}()

// corpusFor returns the typosquat reference corpus for an ecosystem, and
// whether one exists. Checks must not silently score against the wrong
// ecosystem's names — comparing a Python package to npm names would generate
// confident nonsense. Ecosystems without a corpus (gem, cargo, composer, nuget)
// are skipped rather than mis-scored (D-15). Adding a corpus for a new
// ecosystem requires a curated list of popular packages plus a legitimate
// near-neighbour allowlist.
func corpusFor(ecosystem string) ([]string, map[string]struct{}, bool) {
	switch ecosystem {
	case "npm":
		return popularNpm, popularNpmSet, true
	case "pypi":
		return popularPyPI, popularPyPISet, true
	default:
		return nil, nil, false
	}
}
