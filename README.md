<div align="center">

# 📋 ClipBin

### *Secure, shareable clipboard for modern teams*

<p align="center">
  <img src="https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square" alt="License">
  <img src="https://img.shields.io/github/contributors/alight659/ClipBin?style=flat-square&color=success" alt="Contributors">
  <img src="https://img.shields.io/github/stars/alight659/ClipBin?style=flat-square&color=yellow" alt="Stars">
  <img src="https://img.shields.io/github/issues/alight659/ClipBin?style=flat-square&color=red" alt="Issues">
  <img src="https://img.shields.io/badge/coverage-90%25-brightgreen?style=flat-square" alt="Coverage">
</p>

<p align="center">
  <strong>Share code snippets, configurations, and text securely with password protection, expiring links, and custom aliases.</strong>
</p>

[Features](#-features) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Contributing](#-contributing) • [Support](#-support)

<img src="https://user-images.githubusercontent.com/placeholder/demo.gif" alt="ClipBin Demo" width="800">

---

</div>

## ✨ Features

<table>
<tr>
<td width="50%">

### 🎨 **Beautiful Dark Theme**
Carefully crafted interface optimized for comfortable reading and extended coding sessions.

### 🔐 **End-to-End Encryption**
Optional password protection with client-side encryption ensures your sensitive data stays private.

### ⏱️ **Smart Expiration**
Configurable retention periods from 1 hour to permanent storage—perfect for temporary shares.

</td>
<td width="50%">

### 🎯 **Custom Aliases**
Create memorable URLs like `clipb.in/my-config` instead of random identifiers.

### 📁 **File Upload Support**
Drag and drop or upload text-based files directly—no copy-paste required.

### 🚀 **REST API**
Full-featured API for automation, CI/CD integration, and programmatic access.

</td>
</tr>
</table>

<details>
<summary><strong>🎁 More Features</strong></summary>

- ✅ **Anonymous & Authenticated Modes** – Use without an account or sign in for advanced features
- ✅ **User Dashboard** – Manage all your clips in one centralized location
- ✅ **Export Options** – Download clips as JSON, CSV, or plain text
- ✅ **Raw Endpoints** – Direct plaintext access via `/raw` for automation
- ✅ **Editable Clips** – Allow others to modify your shared content
- ✅ **Syntax Highlighting** – Beautiful code rendering for 100+ languages
- ✅ **Mobile Responsive** – Perfect experience on any device

</details>

---

## 🚀 Quick Start

### Prerequisites

```bash
Python 3.10+  |  pip 22+  |  venv (recommended)
```

### Installation

```bash
# Clone the repository
git clone https://github.com/alight659/ClipBin
cd ClipBin

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### Launch Development Server

```bash
# Option 1: Direct launch
python3 app.py

# Option 2: Using Makefile (recommended)
make dev

# Server starts at http://127.0.0.1:5000
```

> 💡 **Pro Tip:** Use `make help` to see all available commands!

---

## 🛠️ Tech Stack

<div align="center">

### Frontend
![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
![TailwindCSS](https://img.shields.io/badge/Tailwind-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)

### Backend
![Python](https://img.shields.io/badge/Python_3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-07405E?style=for-the-badge&logo=sqlite&logoColor=white)
![Jinja2](https://img.shields.io/badge/Jinja2-B41717?style=for-the-badge&logo=jinja&logoColor=white)

</div>

---

## ⚙️ Configuration

<table>
<thead>
<tr>
<th>Variable</th>
<th>Description</th>
<th>Default</th>
</tr>
</thead>
<tbody>
<tr>
<td><code>SECRET_KEY</code></td>
<td>🔑 Session encryption key <strong>(required in production)</strong></td>
<td><em>None</em></td>
</tr>
<tr>
<td><code>MAX_CONTENT_LENGTH</code></td>
<td>📦 Maximum upload size for clips and files</td>
<td>1.5 MB</td>
</tr>
</tbody>
</table>

**Setting Environment Variables:**

```bash
# Linux/macOS
export SECRET_KEY="your-super-secret-key-here"

# Windows
set SECRET_KEY=your-super-secret-key-here
```

> ⚠️ **Security Note:** Always use a strong, random SECRET_KEY in production. Generate one with:
> ```bash
> python -c "import secrets; print(secrets.token_hex(32))"
> ```

**Data Storage:**  
ClipBin uses `clipbin.db` (SQLite) for data persistence. Back up this file regularly!

---

## 🧪 Testing

ClipBin maintains **90%+ test coverage** with comprehensive testing across all components.

### Quick Testing Commands

```bash
# View all test options
make help

# Run fast tests (recommended for development)
make test-fast

# Run tests with coverage report
make test-coverage

# Run specific test suites
make test-unit          # Unit tests only
make test-integration   # Integration tests
```

### Manual Testing

```bash
# Run all tests
python -m pytest

# Run with coverage
python -m pytest --cov=. --cov-report=html

# Run specific test files
python -m pytest tests/test_additional.py -v

# Use the test runner script
python run_tests.py --fast
```

### Test Coverage Breakdown

- ✅ **Unit Tests** – Individual function validation
- ✅ **Integration Tests** – Complete workflow testing
- ✅ **Security Tests** – XSS & SQL injection prevention
- ✅ **API Tests** – REST endpoint validation
- ✅ **Database Tests** – SQLite operations & integrity

<div align="center">

**Current Coverage:** `additional.py: 100%` • `sqlite.py: 100%` • `app.py: Comprehensive`

</div>

---

## 📖 Documentation

### Usage Guide

1. **Create a Clip**  
   Visit the homepage and enter your title and content, or upload a file

2. **Configure Options**  
   Set password protection, expiration time, custom alias, or edit permissions

3. **Share the Link**  
   Copy and share the generated URL with your team or friends

4. **Access Variants**  
   - **View:** `clipb.in/<id>` – Full web interface  
   - **Raw:** `clipb.in/raw/<id>` – Plain text  
   - **Download:** `clipb.in/download/<id>` – File download

5. **User Dashboard** *(authenticated users)*  
   Manage all clips, view analytics, and export data

### API Endpoints

```bash
# Create a clip
POST /api/clips
Content-Type: application/json
{
  "title": "My Config",
  "content": "...",
  "password": "optional",
  "expires": "1h"
}

# Retrieve a clip
GET /api/clips/<id>

# Update a clip (if editable)
PATCH /api/clips/<id>

# Delete a clip
DELETE /api/clips/<id>
```

---

## 🤝 Contributing

We love contributions! Whether it's bug fixes, new features, or documentation improvements—all are welcome.

### How to Contribute

1. 📖 Read our [Contributing Guidelines](./CONTRIBUTING.md) and [Code of Conduct](./CODE_OF_CONDUCT.md)
2. 🍴 Fork the repository and create a feature branch
3. 💻 Make your changes with clear commit messages
4. ✅ Add tests and update documentation
5. 🚀 Open a pull request with a detailed description

**Looking for ideas?** Check out [good first issues](https://github.com/alight659/ClipBin/labels/good%20first%20issue) and [help wanted](https://github.com/alight659/ClipBin/labels/help%20wanted) tags!

### Contributors Wall

<div align="center">

**Thank you to all our amazing contributors! ❤️**

<a href="https://github.com/alight659/ClipBin/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=alight659/ClipBin&max=100" />
</a>

</div>

---

## 💬 Support

<table>
<tr>
<td align="center" width="33%">

### 📧 Email
[aanis@clipb.in](mailto:aanis@clipb.in)

</td>
<td align="center" width="33%">

### 🐛 Bug Reports
[GitHub Issues](https://github.com/alight659/ClipBin/issues)

</td>
<td align="center" width="33%">

### 💡 Feature Requests
[Discussions](https://github.com/alight659/ClipBin/discussions)

</td>
</tr>
</table>

---

## 📄 License

ClipBin is open source software licensed under the [MIT License](./LICENSE).

<div align="center">

---

**Built with ❤️ by the ClipBin Community**

[⭐ Star us on GitHub](https://github.com/alight659/ClipBin) • [🐦 Follow updates](#) • [📚 Read the docs](#)

ClipBin is released under the [MIT License](./LICENSE).
