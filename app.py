import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
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
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # extract user holdings
    user_holdings = db.execute("SELECT * FROM holdings WHERE id=?", session["user_id"])

    # extract total balance
    current_cash = db.execute("SELECT cash FROM users where id=?", session["user_id"])[0]["cash"]

    # get final total
    total_cash = current_cash
    for holding in user_holdings:
        total_cash += holding["total_price"]

    return render_template("index.html", user_holdings=user_holdings, current_cash=current_cash, total_cash=total_cash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    # user buying shares

    # user request via post
    if request.method == "POST":

        # get input symbol and check validity
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Enter valid input", 400)
        elif lookup(symbol) == None:
            return apology("Symbol does not exist", 400)

        # get input shares and check validity
        shares = request.form.get("shares")
        if not shares:
            return apology("Enter valid input", 400)
        try:
            if int(shares) <= 0:
                return apology("Enter valid input", 400)
        except ValueError:
            return apology("Enter valid input", 400)

        # get existing cash from user
        old_cash = db.execute("SELECT cash FROM users WHERE id=?", session["user_id"])[0]["cash"]

        # check if cash is sufficient and buy the share and record
        if old_cash < int(shares) * lookup(symbol)["price"]:
            return apology("Insufficient balance", 403)

        else:
            bought_cash = int(shares) * lookup(symbol)["price"]
            balance = old_cash - bought_cash
            db.execute("UPDATE users SET cash=? WHERE id=?", balance, session["user_id"])
            db.execute("INSERT INTO portfolio (id, method, symbol, shares, current_price, time, name) VALUES(:i, :m, :sym, :shr, :p, :t, :n)",
                       i=session["user_id"], m="Buy", sym=symbol, shr=int(shares), p=lookup(symbol)["price"],
                       t=datetime.now().strftime("%d/%m/%y %H:%M"), n=lookup(symbol)["name"])

        # record transaction to holdings table
            rows = db.execute("SELECT * FROM holdings WHERE id=? AND symbol=?", session["user_id"], symbol)
            if len(rows) == 0:
                db.execute("INSERT INTO holdings (id, symbol, shares, current_price, total_price) VALUES(:i, :sym, :shr, :cur_p, :tot)",
                            i=session["user_id"], sym=symbol, shr=int(shares), cur_p=lookup(symbol)["price"], tot=bought_cash)
            else:
                tot_shares = rows[0]["shares"] + shares
                tot_amount = tot_shares * lookup(symbol)["price"]
                db.execute("UPDATE holdings SET shares=:shr AND total_price=:tot WHERE id=:id AND symbol=:sym",
                           shr=tot_shares, tot=tot_amount, id=session["user_id"], sym=symbol)

        # backto hompeage
        return redirect("/")
    else:
    # user request via get
        return render_template("buy.html")

@app.route("/history")
@login_required
def history():
    """display transaction history of user"""
    history = db.execute(
        "SELECT symbol, method, shares, current_price, time FROM portfolio WHERE id=? ORDER BY trans_id", session["user_id"])
    return render_template("history.html", history=history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    # user reached via post
    if request.method == "POST":

        # lookup quote for the symbol
        quotes = lookup(request.form.get("symbol"))
        if quotes == None:
            return apology("No quote found", 400)

        # return to the quoted page
        return render_template("quoted.html", quotes=quotes)
    else:
        # user reached via get
        return render_template("quote.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    # Forget any user_id
    session.clear()

    # user reached via post
    if request.method == "POST":

        # get username and check validity and originality
        name = request.form.get("username")
        rows = db.execute("SELECT * FROM users WHERE username = ?", name)
        if not name:
            return apology("Must provide username", 400)
        elif len(rows) != 0:
            return apology("Username exists", 400)

        # get password and confirm
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not password or not confirmation:
            return apology("Must provide password", 400)
        elif password != confirmation:
            return apology("Passwords do not match", 400)

        # register user into db
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", name, generate_password_hash(password))
        id = db.execute("SELECT id FROM users WHERE username=?", name)[0]["id"]

        session["user_id"] = id

        # redirect to login
        return redirect("/login")
    else:
        #user reached via get
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # user reached via post
    if request.method == "POST":

        # get input symbol and check validity
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Enter valid input", 400)
        elif lookup(symbol) == None:
            return apology("Symbol does not exist", 400)

        # get input shares and check validity
        shares = request.form.get("shares")
        if not shares:
            return apology("Enter valid input", 400)
        try:
            if int(shares) <= 0:
                return apology("Enter valid input", 400)
        except ValueError:
            return apology("Enter valid input", 400)

        # get available shares of user
        old_shares = db.execute("SELECT * FROM holdings WHERE id=? AND symbol=?", session["user_id"], symbol)
        if len(old_shares) == 0:
            return apology("No shares owned", 400)
        elif int(shares) > old_shares[0]["shares"]:
            return apology("Insuficient shares", 400)

        ##update sold shares in portfolio
        old_cash= db.execute("SELECT * FROM users WHERE id=?", session["user_id"])[0]["cash"]
        balance = old_cash + (int(shares) * lookup(symbol)["price"])
        db.execute("INSERT INTO portfolio (id, method, symbol, shares, current_price, time, name) VALUES(:i, :m, :sym, :shr, :p, :t, :n)",
                   i=session["user_id"], m="Sell", sym=symbol, shr=shares, p=lookup(symbol)["price"],
                   t=datetime.now().strftime("%d/%m/%y %H:%M"), n=lookup(symbol)["name"])

        # update cash in users
        db.execute("UPDATE users SET cash=? WHERE id=?", balance, session["user_id"] )

        # update in holdings
        tot_shares = old_shares[0]["shares"] - int(shares)
        if tot_shares == 0:
            db.execute("DELETE FROM holdings WHERE id=? AND symbol=?", session["user_id"], symbol)
        else:
            tot_amount = tot_shares * lookup(symbol)["price"]
            db.execute("UPDATE holdings SET shares=:shr AND total_price=:tot WHERE id=:id AND symbol=:sym",
                       shr=tot_shares, tot=tot_amount, id=session["user_id"], sym=symbol)

        # backto homepage
        return redirect("/")

    else:
        # user reached via get
        options = db.execute("SELECT * FROM holdings WHERE id=?", session["user_id"])
        return render_template("sell.html", options=options)