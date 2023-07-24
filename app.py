import os

from cs50 import SQL
from datetime import datetime
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///passwd_manager.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    """List credentials"""
    if request.method == "POST":
        
        rows = db.execute("SELECT * FROM credentials WHERE id = ?", request.form.get("id"))
        
        if len(rows) != 1 or rows[0]["user_id"] != session["user_id"]:
            return apology("Invalid ID", 400)
        
        name = request.form.get("name") if request.form.get("name") else rows[0]["name"]
            
        url = request.form.get("url") if request.form.get("url") else rows[0]["url"]
        url = url if 'https://' in url else 'https://' + url

        username = request.form.get("username") if request.form.get("username") else rows[0]["username"]

        password = request.form.get("password") if request.form.get("password") else rows[0]["password"]

        db.execute('UPDATE credentials SET name = ?, url = ?, username = ?, password = ? WHERE id = ?', name, url, username, password, request.form.get("id"))

        return redirect("/")
    
    else:
        rows = db.execute("SELECT * FROM credentials WHERE user_id = ?", session["user_id"])
        username = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])[0]["username"]

        credentials = []
        for row in rows:
            row["username-quote"] = f"'{row['username']}'"
            row["password-quote"] = f"'{row['password']}'"
            
            credentials.append(row)

        return render_template("index.html", username=username, credentials=credentials)


@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    """Add a credential"""
    if request.method == "POST":

        if not request.form.get("username"):
            return apology("Invalid username", 400)

        elif not request.form.get("password"):
            return apology("Invalid password", 400)
        
        url = request.form.get('url') if 'https://' in request.form.get('url') else 'https://' + request.form.get('url')

        db.execute('INSERT INTO credentials (user_id, username, password, url, name) VALUES(?, ?, ?, ?, ?)', session['user_id'], request.form.get('username'), request.form.get('password'), url, request.form.get('name'))

        return redirect("/")

    else:
        return render_template("add.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password") or not request.form.get("confirmation"):
            return apology("must provide password", 400)

        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords do not match", 400)

        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        if len(rows) != 0:
            return apology("username taken", 400)

        # Query database to create user
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)",
                   request.form.get("username"), generate_password_hash(request.form.get("password")))

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/remove", methods=["GET", "POST"])
@login_required
def remove():
    """Remove a credential"""
    if request.method == "POST":

        if not request.form.get("id"):
            return apology("Invalid ID", 400)

        rows = db.execute("SELECT * FROM credentials WHERE id = ?", request.form.get("id"))
        
        if len(rows) != 1 or rows[0]["user_id"] != session["user_id"]:
            return apology("Invalid ID", 400)
        
        db.execute("DELETE FROM credentials WHERE id = ?", request.form.get("id"))

        return redirect("/")

    else:
        return redirect("/")
