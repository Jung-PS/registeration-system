import json
import os
import secrets
from datetime import datetime
import pytz
import requests
from flask import Flask, make_response, send_file, render_template, request, redirect, flash, url_for, session
from werkzeug.utils import secure_filename
import bcrypt
import cv2

app = Flask(__name__)
#SECRET
app.secret_key = "SECRET"
TURNSTILE_SECRET_KEY = "SECRET"
timezone = pytz.timezone('Asia/Bangkok')
detector = cv2.QRCodeDetector()
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'heic'}

with open("users.json", "r", encoding="utf-8") as file:
    users = json.load(file)
with open("news.json", "r", encoding="utf-8") as file:
    news = json.load(file)

def save_users():
    with open("users.json", "w") as file:
        json.dump(users, file, indent=4)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/")
def home():
    try:
        if "username" in session:
            user_data = users.get(session["username"])
            if user_data['level'] == 'usr':
                return render_template("home.html", username=session["username"], user_data=user_data)
            elif user_data['level'] == 'admin':
                return render_template("admin.html", data=users, new=news, user_data=user_data)
            elif user_data['level'] == 'viewer':
                return render_template("viewer.html", data=users, new=news, user_data=user_data)
            else:
                return render_template("checker.html", data=users, new=news, user_data=user_data)
    except:
            return redirect(url_for("login"))
    return redirect(url_for("login"))

@app.route("/check/<username>", methods=["POST"])
def check(username):
    if "username" in session and (users[session["username"]]["level"] == "admin" or users[session["username"]]["level"] == "checker"):
        if username in users:
            if users[username]["checked"] == "False":
                users[username]["checked"] = "True"
            else:
                users[username]["checked"] = "False"
            users[username]["lastaction"]=session["username"]
            save_users()
    else:
        flash("Rejected request.", "error")
    return redirect(url_for("home"))

@app.route("/reject/<username>", methods=["POST"])
def reject(username):
    if "username" in session and (users[session["username"]]["level"] == "admin" or users[session["username"]]["level"] == "checker"):
        if username in users:
            if users[username]["checked"] == "Rejected":
                users[username]["checked"] = "False"
            else:
                users[username]["checked"] = "Rejected"
            users[username]["lastaction"]=session["username"]
            save_users()
    else:
        flash("Rejected request.", "error")
    return redirect(url_for("home"))


@app.route("/edit_user/<username>", methods=["POST"])
def edit_user(username):
    if "username" not in session or users[session["username"]]["level"] != "admin":
        flash("Rejected request", "error")
        return redirect(url_for("home"))

    new_username = request.form["new_username"]
    new_password = request.form["new_password"]
    new_prefix = request.form["prefix"]
    new_name = request.form["full_name"]
    new_grade = request.form["school_grade"]
    new_school = request.form["school_name"]
    level = request.form["level"]
    new_news = request.form["news"]
    if username in users:
        if new_password:
            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), salt)
            users[username]["password"] = hashed_password.decode('utf-8')
        users[username]["level"] = level
        users[username]["news"] = new_news
        users[username]["prefix"] = new_prefix
        users[username]["school_grade"] = new_grade
        users[username]["school_name"] = new_school
        users[username]["full_name"] = new_name
        if new_username != username:
            users[new_username] = users.pop(username)
        save_users()
        flash("User details updated successfully", "success")
    else:
        flash("User not found", "error")

    return redirect(url_for("home"))


@app.route("/delete_user/<username>", methods=["POST"])
def delete_user(username):
    if "username" not in session or users[session["username"]]["level"] != "admin":
        flash("Rejected Request.", "error")
        return redirect(url_for("home"))

    if username in users:
        del users[username]
        save_users()
        flash(f"User {username} deleted successfully.", "success")
    else:
        flash("User not found.", "error")

    return redirect(url_for("home"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if(news["register"]["status"] == "close"):
            return redirect(url_for("register"))
        turnstile_token = request.form.get("cf-turnstile-response")
        if not turnstile_token:
            flash("Prove you're not a robot", "error")
            return redirect(url_for("register"))
        turnstile_verification_url = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
        turnstile_data = {
            "secret": TURNSTILE_SECRET_KEY,
            "response": turnstile_token,
            "remoteip": request.remote_addr
        }
        turnstile_response = requests.post(turnstile_verification_url, data=turnstile_data)
        turnstile_result = turnstile_response.json()
        if not turnstile_result.get("success", False):
            flash("Prove you're not a robot", "error")
            return redirect(url_for("register"))

        username = request.form.get("username").strip()
        password = request.form.get("password")
        confirmpassword = request.form.get("confirmpassword")
        full_name = request.form.get("full_name").strip()
        prefix = request.form.get("prefix")
        school_grade = request.form.get("school_grade")
        school_name = request.form.get("school_name").strip()
        profile_picture = request.files.get("profile_picture")
        if not all([username, password, confirmpassword, full_name, prefix, school_grade, school_name]):
            flash("This fill is required", "error")
            return redirect(url_for("register"))

        if len(username) > 20 or len(full_name) > 100 or len(school_name) > 100 :
            flash("Malformed request", "error")
            return redirect(url_for("register"))

        if password != confirmpassword:
            flash("Password don't match", "error")
            return redirect(url_for("register"))

        if username in users:
            flash("That username is taken", "error")
            return redirect(url_for("register"))


        # Handle profile picture
        allowed_extensions = {"png", "jpg", "jpeg", "gif", "heic"}
        max_file_size = 10 * 1024 * 1024  # 10 MB
        random_filename = None

        if profile_picture:
            filename = secure_filename(profile_picture.filename)
            extension = filename.rsplit(".", 1)[-1].lower()

            if extension not in allowed_extensions:
                flash("File extensions is not allowed", "error")
                return redirect(url_for("register"))

            if len(profile_picture.read()) > max_file_size:
                flash("File size must be less than 10MB", "error")
                return redirect(url_for("register"))

            profile_picture.seek(0)
            random_filename = f"{secrets.token_hex(16)}.{extension}"
            profile_picture.save(os.path.join('static/uploads', random_filename))

        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        img = cv2.imread('static/uploads/'+random_filename)
        data, bbox, _ = detector.detectAndDecode(img)
        isvalid=True
        if not data:
            data="No QR code found"
            isvalid=False
        for user in users:
            if users[user]["qrdata"] == data:
                isvalid=False
        users[username] = {
            "password": hashed_password.decode("utf-8"),
            "prefix": prefix,
            "school_grade": school_grade,
            "school_name": school_name,
            "full_name": full_name,
            "profile_picture": random_filename,
            "checked": "False",
            "level": "usr",
            "qrdata" : data,
            "isvalid" : isvalid,
            "timestamp" : datetime.now(timezone).strftime("%d-%m-%Y %H:%M:%S"),
            "lastaction" : "None",
            "news" : ""
        }
        save_users()
        flash("Registeration successful", "success")
        return redirect(url_for("login"))

    return render_template("register.html",data=news)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        turnstile_token = request.form.get("cf-turnstile-response")

        # Verify Turnstile CAPTCHA
        if not turnstile_token:
            flash("Prove you're not a robot", "error")
            return redirect(url_for("login"))

        turnstile_verification_url = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
        turnstile_data = {
            "secret": TURNSTILE_SECRET_KEY,
            "response": turnstile_token,
            "remoteip": request.remote_addr
        }
        turnstile_response = requests.post(turnstile_verification_url, data=turnstile_data)
        turnstile_result = turnstile_response.json()

        if not turnstile_result.get("success", False):
            flash("Prove you're not a robot", "error")
            return redirect(url_for("login"))

        if len(password) > 100:
            flash("Malformed request", "error")
            return redirect(url_for("login"))

        if username in users:
            stored_hash = users[username]["password"].encode('utf-8')
            if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                session["username"] = username
                session.permanent = True
                flash("Login successful", "success")
                return redirect(url_for("home"))
            else:
                flash("Invalid username or password", "error")
        else:
            flash("Invalid username or password", "error")

        return redirect(url_for("login"))

    return render_template("login.html",data=news)

@app.route("/logout")
def logout():
    session.pop("username", None)
    flash("Logout successful", "info")
    return redirect(url_for("login"))

    
@app.route("/update_news", methods=["POST"])
def update_news():
    if "username" not in session or users[session["username"]]["level"] != "admin":
        flash("Permission denied.", "error")
        return redirect(url_for("home"))

    title = request.form.get("title").strip()
    content = request.form.get("content").strip()

    if not title or not content:
        flash("Both title and content are required.", "error")
        return redirect(url_for("home"))

    news["news"]["title"] = title
    news["news"]["content"] = content
    with open("news.json", "w", encoding="utf-8") as file:
        json.dump(news, file, indent=4)
    flash("News updated successfully.", "success")
    return redirect(url_for("home"))

@app.route("/update_web", methods=["POST"])
def update_web():
    if "username" not in session or users[session["username"]]["level"] != "admin":
        flash("Permission denied.", "error")
        return redirect(url_for("home"))

    content = request.form.get("content").strip()
    news["web"]["content"] = content
    with open("news.json", "w", encoding="utf-8") as file:
        json.dump(news, file, indent=4)
    flash("Web updated successfully.", "success")
    return redirect(url_for("home"))

@app.route("/update_register", methods=["POST"])
def update_register():
    if "username" not in session or users[session["username"]]["level"] != "admin":
        flash("Permission denied.", "error")
        return redirect(url_for("home"))

    content = request.form.get("content").strip()
    status = request.form.get("status")

    news["register"]["content"] = content
    news["register"]["status"] = status
    with open("news.json", "w", encoding="utf-8") as file:
        json.dump(news, file, indent=4)
    return redirect(url_for("home"))

@app.route("/embed")
def embed():
    return render_template("embed.html",data=news)


if __name__ == "__main__":
    app.run(host='0.0.0.0',debug=True)

