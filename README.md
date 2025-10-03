
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

## Support

For support, email at [aanis@clipb.in](mailto:aanis@clipb.in)


## Authors

- [@alight659](https://www.github.com/alight659)

## Licence
Released under [MIT Licence](https://github.com/alight659/ClipBin/blob/main/LICENSE)
