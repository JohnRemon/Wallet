from flask import Flask, flash, redirect, render_template, request, session, send_file
from cs50 import SQL
from datetime import datetime, timedelta
import csv
import io
from flask_session import Session
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


db = SQL("sqlite:///system.db")

# took this from helpers.py from finance pset


def apology(message, code=400):

    def escape(s):

        for old, new in [
            ("-", "--"),
            (" ", "-"),
            ("_", "__"),
            ("?", "~q"),
            ("%", "~p"),
            ("#", "~h"),
            ("/", "~s"),
            ('"', "''"),
        ]:
            s = s.replace(old, new)
        return s

    return render_template("apology.html", top=code, bottom=escape(message)), code


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


def login_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            return apology("All Fields are required")
        rows = db.execute("SELECT * FROM users WHERE username=?", username)
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            return apology("invalid username and/or password")
        session["user_id"] = rows[0]["id"]
        return redirect("/")
    else:
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username or not password or not confirmation:
            return apology("All Fields are required")
        elif password != confirmation:
            return apology("Passwords Don't Match")
        elif len(db.execute("SELECT * FROM users WHERE username=?", username)) > 0:
            return apology("User Already Exists")
        else:

            db.execute("INSERT INTO users (username, hash) VALUES(?, ?)",
                       username, generate_password_hash(password))
            user_id = db.execute("SELECT id FROM users WHERE username=?", username)[0]["id"]
            session["user_id"] = user_id
            return redirect("/")
    else:
        return render_template("register.html")


@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect("/")


@app.route("/", methods=["GET", "POST"])
def home():
    #used to chatgpt for the logic for plugging information into the graphs
    if "user_id" in session:
        categories = db.execute("SELECT * FROM categories")
        accounts = db.execute("SELECT * FROM accounts WHERE user_id=?", session["user_id"])
        cash = db.execute("SELECT SUM(balance) FROM accounts WHERE type='Cash' AND user_id=?", session["user_id"])
        cashflow = cash[0]['SUM(balance)']

        labels = []
        labels2 = []
        balances = []
        expenses = []
        current_balance = 0
        total_expenses = 0

        if request.method == "POST":
            account_id = request.form.get("account_id")
            period = request.form.get("period")
            start_date = request.form.get("start_date")
            end_date = request.form.get("end_date")

            query = "SELECT * FROM transactions WHERE "
            params = []

            if account_id != "All":
                query += "account_id=? AND "
                params.append(account_id)

            if period == "week":
                query += "time >= DATE('now', '-7 days') ORDER BY time ASC"
            elif period == "month":
                query += "time >= DATE('now', 'start of month') ORDER BY time ASC"
            elif period == "year":
                query += "time >= DATE('now', 'start of year') ORDER BY time ASC"
            elif period == "custom":
                query += "time BETWEEN ? AND ? ORDER BY time ASC"
                params.append(start_date)
                params.append(end_date)
            else:
                query += "1=1"

            data = db.execute(query, *params)

            for row in data:
                current_balance += row['amount']
                labels.append(row['time'])
                balances.append(current_balance)

            query2 = """
                SELECT c.name AS category_name, SUM(t.amount) AS total_expense
                FROM transactions t
                JOIN categories c ON t.category_id = c.category_id
                WHERE t.amount < 0
            """
            if account_id != "All":
                query2 += " AND t.account_id=?"

            params2 = []
            if account_id != "All":
                params2.append(account_id)

            if period == "week":
                query2 += " AND t.time >= DATE('now', '-7 days')"
            elif period == "month":
                query2 += " AND t.time >= DATE('now', 'start of month')"
            elif period == "year":
                query2 += " AND t.time >= DATE('now', 'start of year')"
            elif period == "custom":
                query2 += " AND t.time BETWEEN ? AND ? "
                params2.extend([start_date, end_date])

            query2 += " GROUP BY c.name"
            data2 = db.execute(query2, *params2)

            for row in data2:
                if 'category_name' in row and 'total_expense' in row:
                    total_expenses += row['total_expense']
                    labels2.append(row['category_name'])
                    expenses.append(-row['total_expense'])

        return render_template("homepage.html", accounts=accounts, categories=categories, labels=labels, labels2=labels2, balances=balances, current_balance=current_balance, expenses=expenses, total_expenses=total_expenses, cashflow=cashflow)
    else:
        return render_template("unregistered-hompage.html")



@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        if not request.form.get("old_password") or not check_password_hash(rows[0]["hash"], request.form.get("old_password")):
            return apology("Invalid Old Password", 400)
        elif not request.form.get("new_password") or not request.form.get("new_password_confirmation"):
            return apology("Please Enter Your New Password")
        elif request.form.get("new_password") != request.form.get("new_password_confirmation"):
            return apology("New Passwords don't match")
        else:
            db.execute("UPDATE users SET hash = ? WHERE id = ?",  generate_password_hash(
                request.form.get("new_password")), session["user_id"])
            flash("Password Changed!")
            return redirect("/")
    else:
        return render_template("change-password.html")


@app.route("/add-record", methods=["GET", "POST"])
@login_required
def add_record():
    categories = db.execute("SELECT * FROM categories")
    sub_categories = db.execute("SELECT * FROM sub_categories")
    accounts = db.execute("SELECT * FROM accounts WHERE user_id=?", session["user_id"])
    if request.method == "POST":

        record_type = request.form.get("recordType")
        description = request.form.get("description")
        sub_category_id = request.form.get("subcategory")
        payee = request.form.get("payee")
        account = request.form.get("account")
        amount = request.form.get("amount")
        category = request.form.get("category")
        date = request.form.get("date")

        if not record_type or not account or not amount or not category or not date:
            return apology("All fields are required")

        amount = float(amount)

        if record_type == "expense":
            amount = -amount
        if sub_category_id and sub_category_id != "default":
            db.execute(
                "INSERT INTO transactions (user_id, account_id, category_id, type, amount, time, description, payee, sub_category_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                session["user_id"], account, category, record_type, amount, date, description, payee, sub_category_id
            )
        else:
            db.execute(
                "INSERT INTO transactions (user_id, account_id, category_id, type, amount, time, description, payee) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                session["user_id"], account, category, record_type, amount, date, description, payee
            )
        if record_type == "expense":
            current_balance = db.execute("SELECT balance FROM accounts WHERE account_id=?", account)[
                0]["balance"]
            exp_balance = current_balance + amount
            db.execute("UPDATE accounts SET balance=? WHERE account_id=?", exp_balance, account)

        elif record_type == "income":
            current_balance = db.execute("SELECT balance FROM accounts WHERE account_id=?", account)[
                0]["balance"]
            inc_balance = current_balance + amount
            db.execute("UPDATE accounts SET balance=? WHERE account_id=?", inc_balance, account)

        flash("Record Added")
        return redirect("/")
    else:
        return render_template("add-record.html", categories=categories, accounts=accounts, sub_categories=sub_categories)


@app.route("/accounts", methods=["GET", "POST"])
@login_required
def accounts():
    accounts = db.execute("SELECT * FROM accounts WHERE user_id=?", session["user_id"])
    if request.method == "POST":
        pass
    else:
        return render_template("accounts.html", accounts=accounts)


@app.route("/accounts/add-account", methods=["GET", "POST"])
@login_required
def add_account():
    if request.method == "POST":
        name = request.form.get("name")
        type = request.form.get("type")
        initial = request.form.get("initial")

        if not name or not type or not initial:
            return apology("All Fields are Required")

        db.execute("INSERT INTO accounts (user_id,name, type, balance) VALUES(?,?,?,?)",
                   session["user_id"], name, type, initial)
        flash("Created New Account")
        return redirect("/")
    else:
        return render_template("add-account.html")


@app.route("/history", methods=["GET", "POST"])
@login_required
def history():
    total_amount = 0
    count = 0
    if request.method == "POST":
        account_id = request.form.get("account")
        category_id = request.form.get("category")
        record_type = request.form.get("record_type")
        payee = request.form.get("payee")
        description = request.form.get("description")
        start_date = request.form.get("start_date")
        end_date = request.form.get("end_date")
        query = """
            SELECT transactions.*,
                categories.name AS category_name,
                accounts.name AS account_name,
                sub_categories.name AS sub_category_name,
                DATE(transactions.time) AS transaction_date
            FROM transactions
            JOIN categories ON transactions.category_id = categories.category_id
            JOIN accounts ON transactions.account_id = accounts.account_id
            LEFT JOIN sub_categories ON transactions.sub_category_id = sub_categories.sub_category_id
            WHERE transactions.user_id = ?
        """
        params = [session["user_id"]]

        if account_id != "All":
            query += " AND transactions.account_id = ?"
            params.append(account_id)
        if category_id != "All":
            query += " AND transactions.category_id = ?"
            params.append(category_id)
        if record_type != "All":
            query += " AND transactions.type = ?"
            params.append(record_type)
        if payee:
            query += " AND payee LIKE ?"
            params.append(f"%{payee}%")
        if description:
            query += " AND description LIKE ?"
            params.append(f"%{description}%")
        if start_date and end_date:
            query += " AND transaction_date BETWEEN ? AND ?"
            params.append(start_date)
            params.append(end_date)
        elif start_date:
            query += " AND transaction_date >= ?"
            params.append(start_date)
        elif end_date:
            query += " AND transaction_date <= ?"
            params.append(end_date)

        query += " ORDER BY transaction_date DESC"
        transactions = db.execute(query, *params)

        if transactions:
            for transaction in transactions:
                total_amount += transaction['amount']
                count += 1

        categories = db.execute("SELECT * FROM categories")
        accounts = db.execute("SELECT * FROM accounts WHERE user_id=?", session["user_id"])

    else:
        transactions = db.execute(
            """SELECT transactions.*,
                categories.name AS category_name,
                accounts.name AS account_name,
                sub_categories.name AS sub_category_name,
                DATE(transactions.time) AS transaction_date
                FROM transactions
                JOIN categories ON transactions.category_id = categories.category_id
                JOIN accounts ON transactions.account_id = accounts.account_id
                LEFT JOIN sub_categories ON transactions.sub_category_id = sub_categories.sub_category_id
                WHERE transactions.user_id = ?
                ORDER BY transactions.time DESC;
            """, session["user_id"])

        categories = db.execute("SELECT * FROM categories")
        accounts = db.execute("SELECT * FROM accounts WHERE user_id=?", session["user_id"])

        if transactions:
            for transaction in transactions:
                total_amount += transaction['amount']
                count += 1

    return render_template("history.html", transactions=transactions, accounts=accounts, categories=categories, total_amount=total_amount, count=count)





@app.route("/accounts/edit/<int:account_id>", methods=["GET", "POST"])
@login_required
def edit_account(account_id):
    account = db.execute("SELECT * FROM accounts WHERE user_id=? AND account_id=?",
                         session["user_id"], account_id)

    if not account:
        return apology("Account not found", 404)

    if request.method == "POST":
        name = request.form.get("name")
        account_type = request.form.get("type")
        initial_amount = request.form.get("initial")

        if not name or not account_type or not initial_amount:
            return apology("All fields are required")

        db.execute(
            "UPDATE accounts SET name = ?, type = ?, balance = ? WHERE user_id = ? AND account_id = ?",
            name, account_type, initial_amount, session["user_id"], account_id
        )
        flash("Account Edited Successfully!")
        return redirect("/accounts")

    return render_template("edit_account.html", account=account[0])


@app.route("/accounts/delete/<int:account_id>", methods=["POST"])
@login_required
def delete_account(account_id):
    account = db.execute(
        "SELECT account_id FROM accounts WHERE user_id=? AND account_id=?", session["user_id"], account_id)
    if not account:
        flash("Account Does Not Exist")
        return redirect("/accounts")
    cash_accounts = db.execute(
        "SELECT account_id FROM accounts WHERE user_id=? AND type=?", session["user_id"], "Cash")
    cash_account_ids = [row['account_id'] for row in cash_accounts]
    if len(cash_account_ids) == 1 and account_id in cash_account_ids:
        flash("You can't delete the only cash account you have")
        return redirect("/accounts")

    db.execute("DELETE FROM accounts WHERE user_id=? AND account_id=?",
               session["user_id"], account_id)

    flash("Account Deleted Successfully")
    return redirect("/accounts")


@app.route("/history/edit/<int:transactions_id>", methods=["GET", "POST"])
@login_required
def edit_transaction(transactions_id):
    transaction = db.execute(
        "SELECT * FROM transactions WHERE user_id=? AND transactions_id=?", session["user_id"], transactions_id)[0]
    if not transaction:
        return apology("Transaction Not Found", 404)
    if request.method == "POST":
        record_type = request.form.get("recordType")
        description = request.form.get("description")
        payee = request.form.get("payee")
        account = request.form.get("account")
        amount = request.form.get("amount")
        category = request.form.get("category")
        time = request.form.get("date")

        if not record_type or not account or not amount or not category or not time:
            return apology("All Fields are Required")

        old_amount = transaction["amount"]
        new_amount = float(amount) if record_type == "income" else -float(amount)
        difference = new_amount - old_amount

        db.execute("UPDATE accounts SET balance = balance + ? WHERE account_id=? AND user_id=?",
                   difference, account, session["user_id"])

        db.execute(
            "UPDATE transactions SET type = ?, account_id = ?, amount = ?, category_id = ?, time = ?, description=?, payee=? WHERE transactions_id = ? AND user_id = ?",
            record_type, account, new_amount, category, time, description, payee, transactions_id, session[
                "user_id"]
        )

        flash("Record Edited Successfully!")
        return redirect("/history")

    accounts = db.execute("SELECT * FROM accounts WHERE user_id=?", session["user_id"])
    categories = db.execute("SELECT * FROM categories")
    sub_categories = db.execute("SELECT * FROM sub_categories")
    return render_template("edit-transaction.html", transaction=transaction, accounts=accounts, categories=categories, sub_categories=sub_categories)


@app.route("/history/delete/<int:transactions_id>", methods=["POST"])
@login_required
def delete_transaction(transactions_id):
    transaction = db.execute(
        "SELECT * FROM transactions WHERE user_id=? AND transactions_id=?", session["user_id"], transactions_id)
    if not transaction:
        return apology("Transaction Does Not Exist")
    db.execute("UPDATE accounts SET balance = balance - ? WHERE account_id=? AND user_id=?",
               transaction[0]["amount"], transaction[0]["account_id"], session["user_id"])
    db.execute("DELETE FROM transactions WHERE user_id=? AND transactions_id=?",
               session["user_id"], transactions_id)
    flash("Transaction Deleted Successfully!")
    return redirect("/history")


@app.route("/accounts/detail/<int:account_id>", methods=["GET", "POST"])
@login_required
def account_detail(account_id):
    today = datetime.today().date()
    one_week_ago = today - timedelta(days=7)

    account = db.execute("SELECT * FROM accounts WHERE user_id=? AND account_id=?",
                         session["user_id"], account_id)[0]
    transactions = db.execute(
        "SELECT transactions.*, categories.name AS category_name, accounts.name AS account_name, DATE(transactions.time) AS transaction_date FROM transactions JOIN categories ON transactions.category_id = categories.category_id JOIN accounts ON transactions.account_id = accounts.account_id WHERE transactions.user_id = ? AND accounts.account_id=? ORDER BY transaction_date DESC", session["user_id"], account_id)
    if not account:
        flash("Account Does Not Exist")
        return redirect("/accounts")

    today_balance = db.execute("""
        SELECT SUM(amount) as balance FROM transactions
        WHERE user_id=? AND account_id=? AND time <= ?
        """, session["user_id"], account_id, today)[0]["balance"]

    previous_week_balance = db.execute("""
        SELECT SUM(amount) as balance FROM transactions
        WHERE user_id=? AND account_id=? AND time <= ?
        """, session["user_id"], account_id, one_week_ago)[0]["balance"]

    today_balance = today_balance if today_balance is not None else 0
    previous_week_balance = previous_week_balance if previous_week_balance is not None else 0

    if previous_week_balance != 0:
        percentage_change = ((today_balance - previous_week_balance) /
                             abs(previous_week_balance)) * 100
    else:
        percentage_change = 0

    return render_template("account-detail.html", account=account, percentage_change=percentage_change, today_balance=today_balance, transactions=transactions)


@app.route("/export", methods=["GET", "POST"])
@login_required
def export():
    # used chat-gpt for the exporting logic
    if request.method == "POST":
        account_id = request.form.get("account")

        # Fetch transactions based on the account_id
        if account_id == "all":
            transactions = db.execute("""SELECT transactions.transactions_id, accounts.name AS account_name, categories.name AS category_name, transactions.type, transactions.amount, transactions.time
                                        FROM transactions
                                        JOIN categories ON transactions.category_id = categories.category_id
                                        JOIN accounts ON transactions.account_id = accounts.account_id
                                        WHERE transactions.user_id=?""", session["user_id"])
        else:
            transactions = db.execute("""SELECT transactions.transactions_id, accounts.name AS account_name, categories.name AS category_name, transactions.type, transactions.amount, transactions.time
                                            FROM transactions
                                            JOIN categories ON transactions.category_id = categories.category_id
                                            JOIN accounts ON transactions.account_id = accounts.account_id
                                            WHERE transactions.user_id = ? AND transactions.account_id = ?""", session["user_id"], account_id)

        # Prepare CSV file
        output = io.StringIO()
        writer = csv.writer(output)
        # Write header
        writer.writerow(['transactions_id', 'account_name', 'category_name', 'type',
                        'amount', 'time'])
        # Write data
        for transaction in transactions:
            writer.writerow([transaction['transactions_id'], transaction['account_name'], transaction['category_name'],
                            transaction['type'], transaction['amount'], transaction['time']])

        output.seek(0)

        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype='text/csv',
            as_attachment=True,
            download_name='transactions.csv'
        )
    else:
        accounts = db.execute("SELECT * FROM accounts WHERE user_id=?", session["user_id"])
        return render_template("export.html", accounts=accounts)
