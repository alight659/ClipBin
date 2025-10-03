from flask import Flask

app = Flask(__name__)

@app.errorhandler(405)
def error_405(e):
    return "405 Method Not Allowed", 405

@app.route("/about")
def about():
    return "About page"

if __name__ == "__main__":
    with app.test_client() as client:
        response = client.get('/about')
        print(f'GET /about: {response.status_code}')
        response = client.post('/about')
        print(f'POST /about: {response.status_code}')