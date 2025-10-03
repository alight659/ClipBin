
# ClipBin

The Simplest way of sharing code or anything that is text.

## Features

- Dark mode
- Anonymous
- Password Protected Bins
- End-To-End Encryption(E2EE)
- Full CRUD Support
- File Upload Support
- Login/Sign-Up Features
- Dashboard Features
- Open API
- Custom URL Alias
- Temporary Time Based Clips
- Data Export Options
- **Many more Coming SOON!**


## Tech Stack

**Client:** HTML, JavaScript, TailwindCSS

**Server:** Python, Flask, Jinja, SQLite3


## Run Locally

Clone the project

```bash
  git clone https://github.com/alight659/ClipBin
```

Go to the project directory

```bash
  cd ClipBin
```

Install dependencies

```bash
  pip3 install -r requirements.txt
```

Start the server

```bash
  python3 app.py
```

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

## CI/CD Pipeline

This project uses automated CI/CD workflows to ensure code quality and prevent breaking changes:

### 🔄 Automated Workflows

- **Pytest CI**: Comprehensive test suite with coverage reporting
- **CI Pipeline**: Code quality, security scanning, and multi-version testing

### 🚀 Quality Gates

Every PR automatically validates:
- ✅ All 147 pytest tests pass
- ✅ Code coverage ≥ 39%
- ✅ Application builds and starts successfully
- ✅ Core endpoints respond correctly
- ✅ Code formatting and linting standards
- ✅ Security vulnerability scanning

![CI Status](https://github.com/yashksaini-coder/ClipBin/actions/workflows/pytest-ci.yml/badge.svg)
![Tests](https://github.com/yashksaini-coder/ClipBin/actions/workflows/ci.yml/badge.svg)

## Testing

This project includes a comprehensive test suite with **147 passing tests** and **64% code coverage**. The tests cover:

- **Unit Tests**: Individual function testing for utility modules (100% coverage)
- **Integration Tests**: Complete workflow testing 
- **Database Tests**: SQLite operations and data integrity (90% coverage)
- **Security Tests**: XSS, SQL injection prevention
- **API Tests**: REST API endpoints and Flask routes

### Quick Testing

```bash
# Run core test suite
make test

# Run tests with coverage report
make test-coverage

# Run tests quickly without coverage
make test-fast
```

### Manual Testing

```bash
# Install dependencies
pip install -r requirements.txt

# Run all tests
python -m pytest tests/ -v

# Run tests with coverage
python -m pytest tests/ --cov=. --cov-report=html

# Run specific test files
python -m pytest tests/test_additional.py tests/test_sqlite.py -v
```

## Support

For support, email at [aanis@clipb.in](mailto:aanis@clipb.in)


## Authors

- [@alight659](https://www.github.com/alight659)

## Licence
Released under [MIT Licence](https://github.com/alight659/ClipBin/blob/main/LICENSE)
