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

ClipBin is a Flask-based web application for storing and sharing code snippets, configuration fragments, and other plaintext securely. It supports authenticated workflows for teams while also allowing anonymous users to create temporary clips with password protection.

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

- Read our [Contributing Guidelines](./CONTRIBUTING.md)
- Follow our [Code of Conduct](./CODE_OF_CONDUCT.md)
- Open an [issue](https://github.com/alight659/ClipBin/issues) or submit a [pull request](https://github.com/alight659/ClipBin/pulls)

---

## Community & Support

Questions, bug reports, or feature ideas are encouraged. Reach the maintainers at [aanis@clipb.in](mailto:aanis@clipb.in) or open a GitHub issue.

---

## License

ClipBin is released under the [MIT License](./LICENSE).
