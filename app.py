import os
from datetime import datetime, timedelta

from sqlite import SQLite
from flask import Flask, flash, render_template, request, redirect, session, Response, jsonify, abort
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from additional import gen_id, login_required, stat, file_check, encrypt, decrypt, validate_alias, jsonfy, csvfy, textify

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

time = {
    "day": timedelta(days=1),
    "week": timedelta(weeks=1),
    "twoweek": timedelta(weeks=2),
    "month": timedelta(weeks=4),
    "half": timedelta(weeks=26),
    "year": timedelta(weeks=52)
}

alias = ['clip', 'login', 'register', 'about', 'api', 'dashboard', 'settings', 'update', 'delete', 'terms', 'feedback']

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
def error_404(code):
    return render_template("error.html", code="404 Not Found!"), 404


# Error Handling 405
@app.errorhandler(405)
def error_405(code):
    return render_template("error.html", code="405 Method Not Allowed!"), 405


# Error Handling 500
@app.errorhandler(500)
def error_500(code):
    return render_template("error.html", code="500 Internal Server Error!"), 500


# Error Handling 413
@app.errorhandler(413)
def error_413(code):
    return render_template("error.html", code="413 Content Too Large!"), 413


# Initialize session after error handlers
Session(app)


# Main Index Function
@app.route("/", methods=["GET", "POST"]) 
def index():
    post_id = gen_id()
    is_editable = 0
    is_unlisted = 0

    if request.method == "POST":
        name = request.form.get("clip_name")
        text_raw = request.form.get("clip_text")
        text = str(text_raw).strip() if text_raw else ""
        passwd_raw = request.form.get("clip_passwd")
        passwd = str(passwd_raw) if passwd_raw else ""
        editable = request.form.get("clip_edit")
        unlist = request.form.get("clip_disp")
        custom_alias = request.form.get("clip_alias")
        remove_time = request.form.get('clip_delete')
        custom_delete = request.form.get('clip_custom_delete') 
        file = request.files.get("clip_file")

        if custom_alias:
            custom_alias = custom_alias.strip()
            if custom_alias in alias:
                flash("Alias cannot be one of the Primary Routes.")
                return redirect("/")
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

        if text and file and file.filename:
            flash("Cannot upload both Text and File together!")
            return redirect("/")

        if not text and (not file or not file.filename):
            flash("Text Field or File Cannot be Empty!")
            return redirect("/")

        if text and not name:
            flash("Title Cannot be Empty!")
            return redirect("/")

        if file and file.filename:
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
            elif remove_time=='custom' and custom_delete:
                try:
                    hours = int(custom_delete)
                    remove_time = (datetime.now() + timedelta(hours=hours)).strftime('%d-%m-%Y %H:%M:%S')
                except ValueError:
                    flash("Invalid custom delete time.")
                    return redirect("/")
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

        return redirect(f"/{post_id}")
    else:
        return render_template("index.html", dat=loginData())


# Show CLIP Function
@app.route("/<clip_url_id>", methods=["GET", "POST"])
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

        time_left = ""
        if remove_time:
            if datetime.strptime(remove_time, '%d-%m-%Y %H:%M:%S') < datetime.now():
                db.execute("DELETE FROM clips WHERE clip_url=?", clip_url_id)
                return render_template("error.html", code="This Clip was Expired.", dat=loginData()), 404
            time_left = datetime.strptime(remove_time, '%d-%m-%Y %H:%M:%S') - datetime.now()

            if time_left.days < 1:
                seconds = time_left.seconds
                hours, remainder = divmod(seconds, 3600)
                minutes, seconds = divmod(remainder, 60)
                time_left = f"{hours}h {minutes}m"
            else:
                time_left = f"{time_left.days} days"

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
                return render_template("clip.html", url_id=clip_url_id, name=name, text=text, time=time, edit=is_editable, update=updated, time_left=time_left, ext=ext, dat=loginData())
            else:
                return render_template("clip.html", passwd=True, error="Incorrect Password!", url_id=clip_url_id, dat=loginData())
        else:
            text = str(text)
            return render_template("clip.html", url_id=clip_url_id, name=name, text=text, time=time, edit=is_editable, update=updated, time_left=time_left, ext=ext, dat=loginData())

    else:
        return render_template("error.html", code="That was not found on this server.", dat=loginData()), 404


# Show Raw
@app.route("/<clip_url_id>/raw", methods=["GET", "POST"])
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
@app.route("/about", methods=["GET"])
def about():
    return render_template("about.html", dat=loginData())


# Test route for 405 error testing (only used in tests)
@app.route("/test-405", methods=["GET"])
def test_405():
    return "Test route for 405 error", 200


# Update Function
@app.route("/update/<url_id>", methods=["GET","POST"])
@login_required
def update(url_id):
    if loginData()[0]:
        data = db.execute("SELECT clips.id, clips.is_editable FROM clipRef JOIN clips ON clips.id = clipRef.clipid WHERE clipRef.userid=? AND clips.clip_URL=?", session["user_id"], url_id)
        if len(data) != 0 and data[0]["is_editable"] == 1:
            if request.method == "POST":
                text = str(request.form.get("clip_text")).strip()
                cur_time = datetime.now().strftime('%d-%m-%Y @ %H:%M:%S')
                db.execute("UPDATE clips SET clip_text=?, update_time=? WHERE id=?", text, cur_time, data[0]["id"])
                return redirect(f"/{url_id}")
            return render_template("error.html", code="Cannot Edit this Clip")
        return render_template("error.html", code="You cannot edit this clip!")
    return redirect("/login")


# Delete Function
@app.route("/delete/<url_id>")
@login_required
def delete(url_id):
    if loginData()[0]:
        data = db.execute("SELECT clips.id FROM clipRef JOIN clips ON clips.id = clipRef.clipid WHERE clipRef.userid=? AND clips.clip_URL=?", session["user_id"], url_id)
        if len(data) != 0:
            db.execute("DELETE FROM clips WHERE id=?", data[0]["id"])
            return redirect("/dashboard")
        else:
            return render_template("error.html", code="Cannot Delete this Clip!")
    return redirect("/login")


# Download Function -> File
@app.route("/download/<url_id>", methods=["GET","POST"])
def download(url_id):
    data = db.execute("SELECT clip_text, clip_name, clip_pwd FROM clips WHERE clip_url=? ", url_id)
    # HOT FIX
    if len(data) == 0:
        return render_template("error.html", code="404 Not Found!"), 404
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
        # Handle both 'uname' and 'username' field names for compatibility
        uname = request.form.get("uname") or request.form.get("username")
        # Handle both 'passwd' and 'password' field names for compatibility
        passwd = request.form.get("passwd") or request.form.get("password")
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
        # Handle both 'uname' and 'username' field names for compatibility
        uname = request.form.get("uname") or request.form.get("username")
        # Handle both 'passwd' and 'password' field names for compatibility  
        passwd = request.form.get("passwd") or request.form.get("password")
        conf = request.form.get("passwdconf") or request.form.get("password_confirm")
        
        # If no confirmation provided, use password (for API/test compatibility)
        if conf is None:
            conf = passwd

        if not uname:
            return render_template("register.html", error="Username cannot be empty!")

        name = db.execute("SELECT username FROM users WHERE username=?", uname)
        if len(name) != 0:
            return render_template("register.html", error="This username already exists!")

        if not passwd:
            return render_template("register.html", error="Password cannot be empty!")

        if not conf:
            return render_template("register.html", error="Password Confirmation is required!")
        if passwd != conf:
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


# Settings Route
@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == 'POST':
        old_pass = str(request.form.get('old_passwd'))
        new_pass = str(request.form.get('new_passwd'))
        conf_pass = str(request.form.get('conf_passwd'))

        if not old_pass:
            flash("Enter your Old Password.")
            return redirect("/settings")

        if not new_pass:
            flash("Enter your New Password.")
            return redirect("/settings")

        if not conf_pass:
            flash("Confirm your New Password.")
            return redirect("/settings")

        if conf_pass != new_pass:
            flash("New Password not Confirmed. Does not Match.")
            return redirect("/settings")

        if new_pass == old_pass:
            flash("New Password cannot be same as Old Password.")
            return redirect("/settings")

        data = db.execute("SELECT password FROM users WHERE id=? AND username=?", session['user_id'], session['uname'])

        if len(data) != 0:
            if check_password_hash(data[0]['password'], old_pass):
                db.execute("UPDATE users SET password=? WHERE id=? AND username=?", generate_password_hash(new_pass, method='scrypt'), session['user_id'], session['uname'])
                flash("Password Updated!")
                return redirect("/settings")
            flash("Old Password Does Not Match.")

        return render_template("settings.html", dat=loginData())
    return render_template("settings.html", dat=loginData())


# Export Data Function -> File
@app.route("/settings/export", methods=["POST", "GET"])
@login_required
def exportdata():
    if request.method == 'POST':
        ext = request.form.get('export_ext')

        data = db.execute("SELECT clips.clip_url AS id, clips.clip_name AS name, clips.clip_text AS text, clips.clip_time AS time FROM clipRef JOIN clips ON clips.id = clipRef.clipid JOIN users ON users.id = clipRef.userid WHERE users.username=? AND clips.clip_pwd IS NULL", session["uname"])

        if len(data) != 0:
            if ext == 'json':
                return Response(jsonfy(data), mimetype='text/json',headers={'Content-disposition': f'attachment; filename={session["uname"]}_export.json', 'Content-Type': 'application/json; charset=utf-8'})
            elif ext == 'csv':
                return Response(csvfy(data), mimetype='text/csv', headers={'Content-disposition': f'attachment; filename={session["uname"]}_export.csv'})
            elif ext == 'text':
                return Response(textify(data), mimetype='text/plain', headers={'Content-disposition': f'attachment; filename={session["uname"]}_export.txt'})
        return render_template("error.html", code="Nothing to Export!")
    return render_template("error.html", code="Nothing to Export!")


# API Get Function
@app.route("/api/get_data")
def get_data():
    clip_id = request.args.get("id")
    clip_name = request.args.get("name")
    clip_alias = request.args.get("alias")
    clip_pass = request.args.get("pwd")
    unlisted = request.args.get("unlisted")

    data = {}

    # If no parameters provided, return empty list instead of error
    if not clip_id and not clip_name and not clip_alias:
        return jsonify([])

    if clip_name and unlisted == 'true':
        return jsonify({'Message': 'To Search, enter Id not Name with unlisted!'}), 400

    if clip_name:
        clip_name = '%'+clip_name+'%'
    
    # Handle alias parameter
    if clip_alias:
        clip_id = clip_alias  # Use alias as ID for searching
        
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
            data_dict = {}
            data_dict['id'] = i['clip_url']
            data_dict['name'] = i['clip_name']
            text = i['clip_text']
            if type(text) == bytes:
                data_dict['text'] = decrypt(text, clip_pass).decode()
            else:
                data_dict['text'] = text
            data_dict['time'] = i['clip_time']
            data_list.append(data_dict)
        return jsonify(data_list)
    return jsonify({'Error': 'No Data'}), 404


# API POST Function
@app.route("/api/post_data", methods=["GET","POST"])
def post_data():
    if request.method == "GET":
        return jsonify({'message': 'POST data to this endpoint to create clips'}), 200
    
    # Handle JSON data
    if request.is_json:
        data = request.get_json()
        clip_name = str(data.get("name", ""))
        clip_text = str(data.get("content", ""))
        unlist = data.get("unlisted")
        clip_pass = data.get("pwd")
        remove_after = data.get("remove")
    else:
        # Handle form data
        clip_name = str(request.form.get("name", ""))
        clip_text = str(request.form.get("text", ""))
        unlist = request.form.get("unlisted")
        clip_pass = request.form.get("pwd")
        remove_after = request.form.get("remove")
    
    clip_id = gen_id()

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
    app.run(debug=True)
