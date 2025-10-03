# ClipBin

> Secure, shareable clipboard for teams and individuals.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Contributors](https://img.shields.io/github/contributors/alight659/ClipBin)](https://github.com/alight659/ClipBin/graphs/contributors)
[![Stars](https://img.shields.io/github/stars/alight659/ClipBin)](https://github.com/alight659/ClipBin/stargazers)
[![Issues](https://img.shields.io/github/issues/alight659/ClipBin)](https://github.com/alight659/ClipBin/issues)

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Running the Development Server](#running-the-development-server)
- [Configuration](#configuration)
- [Usage Guide](#usage-guide)
- [Contributing](#contributing)
- [Community & Support](#community--support)
- [License](#license)

---

## Overview

- Dark mode
- Anonymous
- Password Protected Bins
- End-To-End Encryption(E2EE)
- Full CRUD Support
- File Upload Support
- Login/Sign-Up Features
- Dashboard Features
- Open API with Swagger Documentation
- Custom URL Alias
- Temporary Time Based Clips
- Data Export Options
- **Many more Coming SOON!**

---

## Key Features

- Dark theme interface for comfortable reading.
- Anonymous and authenticated clip creation flows.
- Optional password protection with end-to-end encryption.
- Expiring links with configurable retention periods.
- Custom aliases for easy-to-remember URLs.
- File upload support for vetted text-based formats.
- User dashboard with clip management and exports.
- REST-style API endpoints for automation.

---

## Tech Stack

### Frontend

![HTML](https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white) ![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black) ![TailwindCSS](https://img.shields.io/badge/Tailwind_CSS-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)

### Backend

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white) ![Flask](https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white) ![Jinja2](https://img.shields.io/badge/Jinja2-000000?style=for-the-badge&logo=jinja&logoColor=white) ![SQLite](https://img.shields.io/badge/SQLite-07405E?style=for-the-badge&logo=sqlite&logoColor=white)

---

## Getting Started

### Prerequisites

- Python 3.10 or later
- pip 22+
- (Optional) Virtual environment tooling such as `venv` or `pipenv`

### Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/alight659/ClipBin
cd ClipBin
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### Running the Development Server

Start the Flask application:

```bash
python3 app.py
```

By default the server listens on `http://127.0.0.1:5000`. Enable debug mode locally by editing `app.py` and starting the app with `app.run(debug=True)`.

---

## Configuration

| Variable | Description | Default |
| --- | --- | --- |
| `SECRET_KEY` | Session encryption key used by Flask. **Must** be set in production. | _None_ (Flask will raise if unset) |
| `MAX_CONTENT_LENGTH` | Maximum upload size for clips and files. | 1.5 MB |

Set environment variables in your shell before launching the app, for example:

```bash
export SECRET_KEY="change-me"
```

The application stores data in `clipbin.db`, an SQLite database created on first run. Back up this file for persistence.

---
**Or use the Makefile for easier development:**

```bash
# Start development server
make dev

# Install dependencies
make install

# Run tests quickly
make test-fast

# View all available commands
make help
```

To enable debugging mode, edit app.py

```python
  app.run(debug=True)
```

## API Documentation

ClipBin provides comprehensive API documentation using Swagger/OpenAPI specification:

### Interactive Documentation
- **Swagger UI**: Visit `/docs/` when the server is running to access the interactive API documentation
- **OpenAPI Specification**: The complete API specification is available in `openapi.yaml`

### API Endpoints
- **GET** `/api/get_data` - Retrieve clip data with optional filtering
- **POST** `/api/post_data` - Create new clips with optional password protection and expiration
- **GET/POST** `/{clip_id}/raw` - Access raw clip content

### Accessing Documentation
1. Start the server: `python3 app.py`
2. Open your browser and navigate to: `http://localhost:5000/docs/`
3. Explore the interactive API documentation with live examples

### Updating Documentation
The API documentation is automatically generated from the Flask-RESTX decorators in `app.py`. To update:
1. Modify the API endpoints in `app.py`
2. Update the Swagger models and decorators as needed
3. The documentation will automatically reflect the changes

## Support

## Testing

This project includes a comprehensive test suite using pytest. The tests cover:

- **Unit Tests**: Individual function testing for utility modules
- **Integration Tests**: Complete workflow testing 
- **Database Tests**: SQLite operations and data integrity
- **Security Tests**: XSS, SQL injection prevention
- **API Tests**: REST API endpoints

### Quick Testing with Makefile

The easiest way to run tests is using the provided Makefile:

```bash
# View all available commands
make help

# Run all working tests (recommended)
make test-fast

# Run tests with coverage report
make test-coverage

# Run specific test categories
make test-unit          # Unit tests only
make test-integration   # Integration tests only

# Quick commands
make q                  # Quick test (alias for test-fast)
make qc                 # Quick test with coverage
```

### Manual Testing

Install test dependencies (already included in requirements.txt):

```bash
pip install -r requirements.txt
```

Run all tests:

```bash
python -m pytest
```

Run tests with coverage report:

```bash
python -m pytest --cov=. --cov-report=html
```

Run specific test categories:

```bash
# Run only unit tests
python -m pytest tests/test_additional.py tests/test_sqlite.py

# Run integration tests
python -m pytest tests/test_integration.py

# Run with verbose output
python -m pytest -v
```

Use the convenient test runner script:

```bash
# Run all tests with coverage
python run_tests.py

# Run fast tests without coverage
python run_tests.py --fast

# Generate HTML coverage report
python run_tests.py --html-report

# Run only unit tests
python run_tests.py --type unit
```

### Test Coverage

The project maintains high test coverage standards:

- **Target Coverage**: 90% minimum, 100% preferred
- **Current Coverage**: 
  - `additional.py`: 100%
  - `sqlite.py`: 100%
  - `app.py`: Comprehensive route and functionality testing

View detailed coverage reports:

```bash
# Generate HTML report
python -m pytest --cov=. --cov-report=html
open htmlcov/index.html  # View in browser
```

### Writing Tests

Tests are organized in the `tests/` directory:

- `test_additional.py`: Utility function tests
- `test_sqlite.py`: Database operation tests  
- `test_app.py`: Flask application route tests
- `test_integration.py`: End-to-end workflow tests
- `conftest.py`: Test configuration and fixtures

---

## Usage Guide

1. Visit the home page and create a clip by entering a title and body or uploading a supported file.
2. Optionally set a password, mark the clip as editable, choose an expiration window, or supply a custom URL alias.
3. Share the resulting link. A separate `/raw` endpoint is available for plaintext retrieval, and `/download/<id>` exposes the content as a file.
4. Create an account to unlock the dashboard, manage existing clips, and export content as JSON, CSV, or plain text.

---

## Contributing

Contributions that improve documentation, add features, or streamline the user experience are welcome. To get started:

1. Review the [Contributing Guidelines](./CONTRIBUTING.md) and [Code of Conduct](./CODE_OF_CONDUCT.md).
2. Fork the repository and create a feature branch referencing the related issue.
3. Write clear commit messages and include tests or documentation updates when they apply.
4. Open a pull request explaining the motivation and testing performed.

Need inspiration? Check the [issue tracker](https://github.com/alight659/ClipBin/issues) for help wanted and good first issues.

### We ❤️ contributions!

<a href="https://github.com/alight659/ClipBin/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=alight659/ClipBin&max=10" />
</a>

## Community & Support

Questions, bug reports, or feature ideas are encouraged. Reach the maintainers at [aanis@clipb.in](mailto:aanis@clipb.in) or open a GitHub issue.

---

## License

ClipBin is released under the [MIT License](./LICENSE).