import os

from cs50 import SQL
from flask import Flask, flash, render_template, request, redirect, session, Response
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from additional import gen_id, login_required, stat

app = Flask(__name__)

# Connect to SQLITE3 Database
db = SQL("sqlite:///clipbin.db")


# Custom Filter JINJA
app.jinja_env.filters["stat"] = stat


# Configure Login Session Cache
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


# Set Login Data
def loginData():
    login=False
    name=""
    try:
        if int(session["user_id"]):
            login=True
            name = session["uname"]
    except KeyError:
        login=False
    return [login, name]


# Error Handling 404
@app.errorhandler(404)
def error(code):
    return render_template("error.html", code=code)


# Error Handling 500
@app.errorhandler(500)
def error(code):
    return render_template("error.html", code=code)


# Main Index Function
@app.route("/", methods=["GET", "POST"]) 
def index():
    post_id = gen_id()
    is_editable = 0
    is_unlisted = 0

    if request.method == "POST":
        name = request.form.get("clip_name")
        text = str(request.form.get("clip_text")).strip()
        passwd = str(request.form.get("clip_passwd"))
        editable = request.form.get("clip_edit")
        unlist = request.form.get("clip_disp")

        if editable:
            is_editable = 1
        
        if unlist:
            is_unlisted = 1

        if not passwd:
            db.execute("INSERT INTO clips (clip_url, clip_name, clip_text, is_editable, is_unlisted, clip_time) VALUES (?, ?, ?, ?, ?, datetime('now', 'localtime'))", str(
            post_id), name, text, is_editable, is_unlisted)
        else:
            pwd = generate_password_hash(passwd)
            db.execute("INSERT INTO clips (clip_url, clip_name, clip_text, clip_pwd, is_editable, is_unlisted, clip_time) VALUES (?, ?, ?, ?, ?, ?, datetime('now', 'localtime'))", str(
            post_id), name, text, pwd, is_editable, is_unlisted)

        if loginData()[0]:
            uid = db.execute("SELECT id FROM users WHERE username=?", loginData()[1])[0]["id"]
            cid = db.execute("SELECT id FROM clips WHERE clip_url=?", str(post_id))[0]["id"]
            db.execute("INSERT INTO clipRef (userid, clipid) VALUES (?, ?)", int(uid), int(cid))

        return redirect(f"/clip/{post_id}")
    else:
        return render_template("index.html", dat=loginData())


# Show CLIP Function
@app.route("/clip/<clip_url_id>", methods=["GET", "POST"])
def clip(clip_url_id):
    data = db.execute("SELECT clip_name, clip_text, clip_time, clip_pwd, is_editable, update_time FROM clips WHERE clip_url=?", clip_url_id)
    passwd = ""
    is_editable = False
    if len(data) != 0:
        text = str(data[0]["clip_text"])
        name = data[0]["clip_name"]
        time = data[0]["clip_time"]
        passwd = data[0]["clip_pwd"]
        editable = data[0]["is_editable"]
        updated = data[0]["update_time"]

        if editable == 1:
            is_editable = True

        if passwd and request.method != "POST":
            return render_template("clip.html", passwd=True, url_id=clip_url_id, dat=loginData())
        elif request.method == "POST":
            clip_passwd = request.form.get("clip_passwd")
            
            if check_password_hash(passwd, clip_passwd):
                return render_template("clip.html", url_id=clip_url_id, name=name, text=text, time=time, edit=is_editable, update=updated,  dat=loginData())
            else:
                return render_template("clip.html", passwd=True, error="Incorrect Password!", url_id=clip_url_id, dat=loginData())
        else:
            return render_template("clip.html", url_id=clip_url_id, name=name, text=text, time=time, edit=is_editable, update=updated, dat=loginData())

    else:
        return render_template("error.html", code="That was not found on this server.")


# Search Function
@app.route("/clip", methods=["GET","POST"])
def search():
    if request.method == "POST":
        clip_info = request.form.get("clip_info")
        if not clip_info:
            return render_template("search.html", error="Search Field cannot be empty!", dat=loginData())
        info = str("%"+clip_info+"%")
        data = db.execute("SELECT clip_name, clip_url, clip_time FROM clips WHERE clip_url LIKE ? AND is_unlisted!=1 OR clip_name LIKE ? AND is_unlisted!=1", info, info)
        if len(data) != 0:
            return render_template("search.html", data=data, dat=loginData())
        return render_template("search.html", error="Nothing was found!", dat=loginData())
    return render_template("search.html", dat=loginData())


# Render About Page
@app.route("/about")
def about():
    return render_template("about.html", dat=loginData())


# Update Function
@app.route("/update/<url_id>", methods=["GET","POST"])
def update(url_id):
    if loginData()[0]:
        data = db.execute("SELECT clips.id, clips.is_editable FROM clipRef JOIN clips ON clips.id = clipRef.clipid WHERE clipRef.userid=? AND clips.clip_URL=?", session["user_id"], url_id)
        if len(data) != 0 and data[0]["is_editable"] == 1:
            if request.method == "POST":
                text = str(request.form.get("clip_text")).strip()
                db.execute("UPDATE clips SET clip_text=?, update_time=datetime('now', 'localtime') WHERE id=?", text, data[0]["id"])
                return redirect(f"/clip/{url_id}")
            return render_template("error.html", code="Cannot Edit this Clip")
        return render_template("error.html", code="This Clip Cannot be Edited!")
    return redirect("/login")


# Delete Function
@app.route("/delete/<url_id>")
def delete(url_id):
    if loginData()[0]:
        data = db.execute("SELECT clips.id FROM clipRef JOIN clips ON clips.id = clipRef.clipid WHERE clipRef.userid=? AND clips.clip_URL=?", session["user_id"], url_id)
        if len(data) != 0:
            db.execute("DELETE FROM clipRef WHERE clipid=?", data[0]["id"])
            db.execute("DELETE FROM clips WHERE id=?", data[0]["id"])
            return redirect("/dashboard")
        else:
            return render_template("error.html", code="Cannot Delete this Clip!")
    return redirect("/login")


# Download Function
@app.route("/download/<url_id>")
def download(url_id):
    data = db.execute("SELECT clip_text, clip_name FROM clips WHERE clip_url=?", url_id)
    text = str(data[0]["clip_text"])
    name = data[0]["clip_name"]
    return Response(text, mimetype='text/plain',headers={'Content-disposition': f'attachment; filename={name}.txt'})


# Login Function
@app.route("/login", methods=["GET", "POST"])
def login():

    session.clear()

    if request.method == "POST":
        uname = request.form.get("uname")
        passwd = request.form.get("passwd")
        if not uname:
            return render_template("error.html", code="Username cannot be empty.")

        if not passwd:
            return render_template("error.html", code="Password cannot be empty.")

        data = db.execute("SELECT * FROM users WHERE username=?", uname)
        if len(data) != 0:
            if check_password_hash(data[0]["password"], passwd):
                session["user_id"] = data[0]["id"]
                session["uname"] = uname
                return redirect("/")
        else:
            flash("Account Not Found!")

    return render_template("login.html")


# Logout Function
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# Registration Function
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        uname = request.form.get("uname")
        passwd = request.form.get("passwd")
        conf = request.form.get("passwdconf")

        if not uname:
            return render_template("register.html", error="Username cannot be empty!")

        name = db.execute("SELECT username FROM users WHERE username=?", uname)
        if len(name) != 0:
            return render_template("register.html", error="This username already exists!")

        if not passwd:
            return render_template("register.html", error="Password cannot be empty!")

        if not conf:
            return render_template("register.html", error="Password Confirmation is required!")
        if check_password_hash(passwd, conf):
            return render_template("register.html", error="Passwords do not match!")

        db.execute("INSERT INTO users (username, password) VALUES (?, ?)", uname, generate_password_hash(passwd))

        return redirect("/login")
    return render_template("register.html")


# Dashboard Function
@app.route("/dashboard")
@login_required
def dashboard():
    uname = loginData()[1]
    data = db.execute("SELECT clips.clip_name, clips.clip_url, clips.clip_time, clips.is_editable, clips.is_unlisted FROM clipRef JOIN clips ON clips.id = clipRef.clipid JOIN users ON users.id = clipRef.userid WHERE users.username=?", session["uname"])
    return render_template("dash.html", dat=loginData(), data=data)


if __name__ == "__main__":
    app.run()
