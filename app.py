import os
from datetime import datetime, timedelta

from sqlite import SQLite
from flask import Flask, flash, render_template, request, redirect, session, Response, jsonify, abort
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from additional import gen_id, login_required, stat, file_check, encrypt, decrypt, validate_alias
import qrcode
import io
import base64
from io import BytesIO

app = Flask(__name__)

# Connect to SQLITE3 Database
db = SQLite("clipbin.db")


# Custom Filter JINJA
app.jinja_env.filters["stat"] = stat


# Configure Flask, Login Session Cache
app.config['MAX_CONTENT_LENGTH'] = 1.5 * 1024 * 1024
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.secret_key = os.environ.get("SECRET_KEY")
Session(app)

time = {
    "day": timedelta(days=1),
    "week": timedelta(weeks=1),
    "twoweek": timedelta(weeks=2),
    "month": timedelta(weeks=4),
    "half": timedelta(weeks=26),
    "year": timedelta(weeks=52)
}

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
    return render_template("error.html", code="404 Not Found!"), 404


# Error Handling 500
@app.errorhandler(500)
def error(code):
    return render_template("error.html", code="500 Internal Server Error!"), 500


# Error Handling 413
@app.errorhandler(413)
def error(code):
    return render_template("error.html", code="413 Content Too Large!"), 413


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
        custom_alias = request.form.get("clip_alias")
        remove_time = request.form.get('clip_delete')
        file = request.files["clip_file"]

        if custom_alias:
            custom_alias = custom_alias.strip()
            if not validate_alias(custom_alias):
                flash("Alias must be 4-12 characters long and contain only letters, numbers, hyphens and underscores!")
                return redirect("/")
            check = db.execute("SELECT clip_url from clips WHERE clip_url=?", custom_alias)
            if len(check) != 0:
                flash("This alias is already taken!")
                return redirect("/")
            post_id = custom_alias
        
        if editable:
            is_editable = 1
        
        if unlist:
            is_unlisted = 1

        if text and file:
            flash("Cannot upload both Text and File together!")
            return redirect("/")

        if not text and not file:
            flash("Text Field or File Cannot be Empty!")
            return redirect("/")

        if text and not name:
            flash("Title Cannot be Empty!")
            return redirect("/")

        if file:
            if file_check(file.filename):
                text = str(file.read().decode("utf-8"))
            else:
                flash("File Not Allowed!")
                return redirect("/")
            if not name:
                name = secure_filename(file.filename)

        if editable:
            is_editable = 1
        
        if unlist:
            is_unlisted = 1

        check = db.execute("SELECT clip_url from clips WHERE clip_url=?", post_id)
        if len(check) != 0:
            if not custom_alias:
                post_id = gen_id()
            else:
                flash("This alias is already taken!")
                return redirect("/")

        if remove_time:
            if remove_time == 'never':
                remove_time = None
            else:
                remove_time = (time[remove_time] + datetime.now()).strftime('%d-%m-%Y %H:%M:%S')

        cur_time = datetime.now().strftime('%d-%m-%Y @ %H:%M:%S')
        if not passwd:
            db.execute("INSERT INTO clips (clip_url, clip_name, clip_text, is_editable, is_unlisted, clip_time, delete_time) VALUES (?, ?, ?, ?, ?, ?, ?)", str(
            post_id), name, text, is_editable, is_unlisted, cur_time, remove_time)
        else:
            pwd = generate_password_hash(passwd, method='scrypt')
            text = encrypt(text.encode(), passwd)
            db.execute("INSERT INTO clips (clip_url, clip_name, clip_text, clip_pwd, is_editable, is_unlisted, clip_time, delete_time) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", str(
            post_id), name, text, pwd, is_editable, is_unlisted, cur_time, remove_time)

        if loginData()[0]:
            uid = db.execute("SELECT id FROM users WHERE username=?", loginData()[1])[0]["id"]
            cid = db.execute("SELECT id FROM clips WHERE clip_url=?", str(post_id))[0]["id"]
            db.execute("INSERT INTO clipRef (userid, clipid) VALUES (?, ?)", int(uid), int(cid))

        return redirect(f"/clip/{post_id}")
    else:
        return render_template("index.html", dat=loginData())


# Redirect
@app.route("/<url>")
def urlsrdir(url):
    return redirect(f"/clip/{url}")


# Show CLIP Function
@app.route("/clip/<clip_url_id>", methods=["GET", "POST"])
def clip(clip_url_id):
    data = db.execute("SELECT clip_name, clip_text, clip_time, clip_pwd, is_editable, update_time, delete_time FROM clips WHERE clip_url=?", clip_url_id)
    passwd = ""
    is_editable = False
    if len(data) != 0:
        text = data[0]["clip_text"]
        name = data[0]["clip_name"]
        time = data[0]["clip_time"]
        passwd = data[0]["clip_pwd"]
        editable = data[0]["is_editable"]
        updated = data[0]["update_time"]
        remove_time = data[0]["delete_time"]
        ext = ""

        # Generate QR code (once)
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )

        qr.add_data(request.url)
        qr.make(fit=True)
        img = qr.make_image(fill='black', back_color='white')

        # Convert to base64
        img_io = BytesIO()
        img.save(img_io, 'PNG')
        img_data = base64.b64encode(img_io.getvalue()).decode('utf-8')

        if remove_time:
            if datetime.strptime(remove_time, '%d-%m-%Y %H:%M:%S') < datetime.now():
                db.execute("DELETE FROM clips WHERE clip_url=?", clip_url_id)
                return render_template("error.html", code="This Clip was Expired.", dat=loginData()), 404

        if editable == 1:
            is_editable = True

        try:
            ext = name.rsplit('.')[1]
        except IndexError:
            ext = 'txt'

        if passwd and request.method != "POST":
            return render_template("clip.html", passwd=True, url_id=clip_url_id, dat=loginData())
        elif request.method == "POST":
            clip_passwd = request.form.get("clip_passwd")
            
            if check_password_hash(passwd, clip_passwd):
                text = decrypt(text, clip_passwd).decode()
                return render_template("clip.html", url_id=clip_url_id, name=name, text=text, time=time, edit=is_editable, update=updated, ext=ext, dat=loginData())
            else:
                return render_template("clip.html", passwd=True, error="Incorrect Password!", url_id=clip_url_id, dat=loginData())
        else:
            text = str(text)
            return render_template("clip.html", url_id=clip_url_id, name=name, text=text, time=time, edit=is_editable,qr_code_img=img_data, update=updated, ext=ext, dat=loginData())

    else:
        return render_template("error.html", code="That was not found on this server.", dat=loginData()), 404


# Show Raw
@app.route("/clip/<clip_url_id>/raw", methods=["GET", "POST"])
def clipraw(clip_url_id):
    data = db.execute("SELECT clip_text, clip_pwd, delete_time FROM clips WHERE clip_url=?", clip_url_id)
    passwd = ""
    if len(data) != 0:
        text = data[0]["clip_text"]
        passwd = data[0]["clip_pwd"]
        remove_time = data[0]["delete_time"]

        if remove_time:
            if datetime.strptime(remove_time, '%d-%m-%Y %H:%M:%S') < datetime.now():
                db.execute("DELETE FROM clips WHERE clip_url=?", clip_url_id)
                return Response("This Clip was Expired.", mimetype='text/plain'), 404

        if passwd and request.method != "POST":
            return Response(f"This Clip is Password Protected. Send a POST request at the url {request.url} with parameter passwd=<your_password>\nExample Request: curl -d \"passwd=<your_password>\" -X POST {request.url}\n", mimetype="text/plain")
        elif request.method == "POST":
            clip_passwd = request.form.get("passwd")
            
            if check_password_hash(passwd, clip_passwd):
                text = decrypt(text, clip_passwd).decode()
                return text, {'Content-Type': 'text/plain'}
            else:
                return Response("Incorrect Password!\n", mimetype='text/plain')
        else:
            text = str(text)
            return text, {'Content-Type': 'text/plain'}
            
    else:
        return Response("That was not found on this server.\n", mimetype='text/plain'), 404


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
                cur_time = datetime.now().strftime('%d-%m-%Y @ %H:%M:%S')
                db.execute("UPDATE clips SET clip_text=?, update_time=? WHERE id=?", text, cur_time, data[0]["id"])
                return redirect(f"/clip/{url_id}")
            return render_template("error.html", code="Cannot Edit this Clip")
        return render_template("error.html", code="You cannot edit this clip!")
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
@app.route("/download/<url_id>", methods=["GET","POST"])
def download(url_id):
    data = db.execute("SELECT clip_text, clip_name, clip_pwd FROM clips WHERE clip_url=? ", url_id)
    text = str(data[0]["clip_text"])
    name = data[0]["clip_name"]
    passwd = data[0]["clip_pwd"]

    if not file_check(name):
        name = name+'.txt'

    if passwd and request.method != "POST":
        return render_template("passwd.html", url_id=url_id)
    elif request.method == "POST":
        clip_passwd = request.form.get("clip_passwd")
            
        if check_password_hash(passwd, clip_passwd):
            return Response(text, mimetype='text/plain',headers={'Content-disposition': f'attachment; filename={name}'})
        else:
            return render_template("passwd.html", error="Incorrect Password!", url_id=url_id)
 
    return Response(text, mimetype='text/plain',headers={'Content-disposition': f'attachment; filename={name}'})


# Login Function
@app.route("/login", methods=["GET", "POST"])
def login():

    session.clear()

    if request.method == "POST":
        uname = request.form.get("uname")
        passwd = request.form.get("passwd")
        if not uname:
            flash("Username Cannot be Empty!")

        if not passwd:
            flash("Password Cannot be Empty!")

        data = db.execute("SELECT * FROM users WHERE username=?", uname)
        if len(data) != 0:
            if check_password_hash(data[0]["password"], passwd):
                session["user_id"] = data[0]["id"]
                session["uname"] = uname
                return redirect("/")
            else:
                flash("Incorrect Username or Password!")
                return render_template("login.html", dat=loginData(), reg=True)
        else:
            flash("Account Not Found!")

    return render_template("login.html", dat=loginData(), reg=True)


# Logout Function
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# Registration Function
@app.route("/register", methods=["GET", "POST"])
def register():

    session.clear()

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

        db.execute("INSERT INTO users (username, password) VALUES (?, ?)", uname, generate_password_hash(passwd, method='scrypt'))

        return redirect("/login")
    return render_template("register.html", dat=loginData())


# Dashboard Function
@app.route("/dashboard")
@app.route("/dashboard/")
@login_required
def dashboard():
    uname = loginData()[1]
    data = db.execute("SELECT clips.clip_name, clips.clip_url, clips.clip_time, clips.is_editable, clips.is_unlisted FROM clipRef JOIN clips ON clips.id = clipRef.clipid JOIN users ON users.id = clipRef.userid WHERE users.username=?", session["uname"])
    return render_template("dash.html", dat=loginData(), data=data)


# API Get Function
@app.route("/api/get_data")
def get_data():
    clip_id = request.args.get("id")
    clip_name = request.args.get("name")
    clip_pass = request.args.get("pwd")
    unlisted = request.args.get("unlisted")

    data = {}

    if not clip_id and not clip_name:
        return jsonify({'Error': 'Missing Parameters!'}), 400

    if clip_name and unlisted == 'true':
        return jsonify({'Message': 'To Search, enter Id not Name with unlisted!'}), 400

    if clip_name:
        clip_name = '%'+clip_name+'%'
        
    query = 0
    if not clip_pass:
        if unlisted == 'true' and clip_id:
            data = db.execute("SELECT clip_url, clip_name, clip_text, clip_time, delete_time, clip_pwd FROM clips WHERE (clip_url LIKE ?) AND is_unlisted == 1 AND clip_pwd IS NULL", str(clip_id))
        else:
            data = db.execute("SELECT clip_url, clip_name, clip_text, clip_time, delete_time, clip_pwd FROM clips WHERE (clip_url LIKE ? OR clip_name LIKE ?) AND is_unlisted != 1 AND clip_pwd IS NULL", str(clip_id), clip_name)
    else:
        if unlisted == 'true' and clip_id:
            data = db.execute("SELECT clip_url, clip_name, clip_text, clip_time, delete_time, clip_pwd FROM clips WHERE (clip_url LIKE ?) AND is_unlisted == 1", str(clip_id))
        else:
            data = db.execute("SELECT clip_url, clip_name, clip_text, clip_time, delete_time, clip_pwd FROM clips WHERE (clip_url LIKE ? OR clip_name LIKE ?) AND is_unlisted != 1", str(clip_id), clip_name)

    if len(data) != 0:
        for i in data:
            if i['delete_time']:
                if datetime.strptime(i['delete_time'], '%d-%m-%Y %H:%M:%S') < datetime.now():
                    db.execute("DELETE FROM clips WHERE clip_url=?", i['clip_url'])
                    data.remove(i)

    data_list = []
    if len(data) != 0:
        if data[0]['clip_pwd'] != None:
            if not check_password_hash(data[0]['clip_pwd'], clip_pass):
                return jsonify({'Error': 'Incorrect Password'}), 401
        for i in data:
            dat = {}
            dat['id'] = i['clip_url']
            dat['name'] = i['clip_name']
            text = i['clip_text']
            if type(text) == bytes:
                dat['text'] = decrypt(text, clip_pass).decode()
            else:
                dat['text'] = text
            dat['time'] = i['clip_time']
            data_list.append(dat)
        return jsonify(data_list)
    return jsonify({'Error': 'No Data'}), 404


# API POST Function
@app.route("/api/post_data", methods=["GET","POST"])
def post_data():
    clip_name = str(request.form.get("name"))
    clip_id = gen_id()
    clip_text = str(request.form.get("text"))
    unlist = request.form.get("unlisted")
    clip_pass = request.form.get("pwd")
    remove_after = request.form.get("remove")

    if remove_after:
        if remove_after in time.keys():
            remove_after = (time[remove_after] + datetime.now()).strftime('%d-%m-%Y %H:%M:%S')
        else:
            remove_after = None
    else:
        remove_after = None

    check = db.execute("SELECT clip_url FROM clips WHERE clip_url=?", clip_id)
    if len(check) != 0:
        clip_id = gen_id()

    if not clip_name or not clip_text:
        return jsonify({'Error': 'Missing Parameters!'}), 400

    if unlist:
        if unlist == 'true':
            unlist = 1
        else:
            unlist = 0
    else:
        unlist = 0

    successStatus = False
    cur_time = datetime.now().strftime('%d-%m-%Y @ %H:%M:%S')
    if not clip_pass:
        db.execute("INSERT INTO clips (clip_url, clip_name, clip_text, is_editable, is_unlisted, clip_time, delete_time) VALUES (?,?,?,0,?,?,?)", str(clip_id), clip_name, clip_text, unlist, cur_time, remove_after)
        successStatus = True
    elif clip_pass:
        pwd = generate_password_hash(clip_pass, method='scrypt')
        clip_text = encrypt(clip_text.encode(), clip_pass) 
        db.execute("INSERT INTO clips (clip_url, clip_name, clip_text, clip_pwd, is_editable, is_unlisted, clip_time, delete_time) VALUES (?,?,?,?,0,?,?,?)", str(clip_id), clip_name, clip_text, pwd, unlist, cur_time, remove_after)
        successStatus = True
    if successStatus:
        return jsonify({'id': str(clip_id),'Message': 'Successfully added!'}), 201
    return jsonify({'Error': 'Couldn\'t add. Something went wrong.'}), 400


# API Documentation Page
@app.route("/api")
@app.route("/api/")
def api():
    return render_template("api.html", dat=loginData())


# Terms and Privacy Policy Page
@app.route("/terms")
def terms():
    return render_template("info.html", terms=True, dat=loginData())


# Feedback Page
@app.route("/feedback")
def feedbackroute():
    return render_template("info.html", feedback=True, dat=loginData())


if __name__ == "__main__":
    app.run()
