
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
- Open API with Swagger Documentation
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

For support, email at [aanis@clipb.in](mailto:aanis@clipb.in)


## Authors

- [@alight659](https://www.github.com/alight659)

## Licence
Released under [MIT Licence](https://github.com/alight659/ClipBin/blob/main/LICENSE)
