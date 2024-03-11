from uuid import uuid4
import re
from functools import wraps
from flask import redirect, session

# generates unique random hex
def gen_id():
    return uuid4().hex

# login decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function

#custom filter JINJA
def stat(s):
    if s == 0:
        return "No"
    elif s == 1:
        return "Yes"