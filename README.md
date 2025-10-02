
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

To enable debugging mode, edit app.py

```python
  app.run(debug=True)
```

## Run with docker

Clone the project

```bash
  git clone https://github.com/alight659/ClipBin
```

Go to the project directory

```bash
  cd ClipBin
```

Build it

```bash
  docker build -t clipbin .
```

Run with volume for the database

```bash
  docker run -p 5000:5000 -v clipbin-db:/app clipbin
```


## Support

For support, email at [aanis@clipb.in](mailto:aanis@clipb.in)


## Authors

- [@alight659](https://www.github.com/alight659)

## Licence
Released under [MIT Licence](https://github.com/alight659/ClipBin/blob/main/LICENSE)
