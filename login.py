# import the Flask class from the flask module
from flask import Flask, render_template, request, session, redirect
from flask.ext.bcrypt import Bcrypt
from functools import wraps
import DBcm
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# create the application object
app = Flask(__name__)
bcrypt = Bcrypt(app)
DBconfig = {'host': '127.0.0.1',
            'user': 'user1',
            'password': 'mypassword',
            'database': 'userDB'}

domain = "http://127.0.0.1:5000/"


# Function to check that the user is logged in
def check_login(func):
    @wraps(func)
    def wrapped_function(*args, **kwargs):
        if "logged_in" in session:
            return func(*args, **kwargs)
        return redirect("/")

    return wrapped_function


# Function to check that the user has permission to view a page
def check_access(func):
    @wraps(func)
    def wrapped_function(*args, **kwargs):
        if "admin" in session:
            return func(*args, **kwargs)
        return redirect("/accesserror")

    return wrapped_function


# Renders the login page
@app.route('/')
def home():
    return render_template('login.html')  # return the login screen


# Renders the post-login page
@app.route('/splash')
@check_login
def welcome():
    return render_template('splash.html')  # render a template, in this case a splash screen


# Renders page 1, a user page
@app.route('/page1')
@check_login
def page_1():
    return render_template('page1.html')  # render a template, in this case an all users page 1


# Renders page 2, a user page
@app.route('/page2')
@check_login
def page_2():
    return render_template('page2.html')  # render a template, in this case an all users page 2


# Renders page 3, an admin page
@app.route('/page3')
@check_login
@check_access
def page_3():
    return render_template('page3.html')  # render a template, in this case an all users page 3


# Renders page 4, an admin page
@app.route('/page4')
@check_login
@check_access
def page_4():
    return render_template('page4.html')  # render a template, in this case an all users page 4


# Renders the access error page, which stops users viewing admin pages
@app.route('/accesserror')
def accesserror():
    return render_template('accesserror.html')


# Renders the registration page
@app.route('/register')
def regpage():
    return render_template('register.html')  # return the login screen


# Handles the registration page inputs
@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        result = check_password(request.form['username'])

        if result:
            error = 'That user name is in use. Please try again.'
        else:
            if request.form['type'] == "admin":
                a = 1
            else:
                a = 0
            send_email(request.form['username'], str(bcrypt.generate_password_hash(request.form['password']))[1:], request.form['email'], a)
            return render_template('waiting.html')
    return render_template('register.html', error=error)


# Handles the sending of registration emails
def send_email(username: str, password: str, email: str, admin: int):
    with DBcm.UseDatabase(DBconfig) as cursor:

        admin_user = 'royalgroupcarlow@gmail.com'
        admin_pass = 'insert password here'

        address = "http://127.0.0.1:5000/check"

        msg = MIMEMultipart('alternative')
        msg['Subject'] = "Verify your email"
        msg['From'] = admin_user
        msg['To'] = email

        text = "\nClick on the following link to verify your registration.\n%s\n" % (address)
        html = """\
        <html>
        <head></head>
        <body>
            <p>
                Please click on the link below to verify your registration<br>
                <a href="%s">%s</a>
            </p>
        </body>
        </html>
        """ % (address, address)

        part1 = MIMEText(text, 'plain')
        part2 = MIMEText(html, 'html')

        msg.attach(part1)
        msg.attach(part2)

        smtpserver = smtplib.SMTP("smtp.gmail.com", 587)
        smtpserver.ehlo()
        smtpserver.starttls()
        smtpserver.ehlo()
        smtpserver.login(admin_user, admin_pass)
        smtpserver.sendmail(admin_user, email, msg.as_string())
        smtpserver.close()

        _SQL = "insert into user (username, password, email, admin, registered) values ('%s', %s, '%s', '%s', '%s')" % (username, password, email, admin, 0)
        cursor.execute(_SQL)


# Renders the registration confirmation screen
@app.route('/check')
def check():
    return render_template('check.html')


# Handles the registration confirmation logic
@app.route('/check', methods=['GET', 'POST'])
def regconfirm():
    error = None
    if request.method == 'POST':
        result = check_password(request.form['username'])

        if not result:
            error = 'Invalid login details. Please try again.'
        else:
            u, p, e, a, r = result
            if not r:
                with DBcm.UseDatabase(DBconfig) as cursor:
                    _SQL = "update user set registered = 1 where username = '%s'" % u
                    cursor.execute(_SQL)
            if bcrypt.check_password_hash(p, request.form['password']):
                session['logged_in'] = True
                if a == 1:
                    session['admin'] = a
                return render_template('splash.html')
            else:
                error = "Incorrect password"
                return render_template('login.html', error=error)
    return render_template('login.html', error=error)


# Handles user logout
@app.route('/logout')
@check_login
def logout():
    session.pop("logged_in")
    if "admin" in session:
        session.pop("admin")
    return redirect("/")


# Handles the login page input
@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        result = check_password(request.form['username'])

        if not result:
            error = 'Invalid login details. Please try again.'
        else:
            u, p, e, a, r = result
            if not r:
                error = "You have not finished registering, check your email"
                return render_template('login.html', error=error)
            elif bcrypt.check_password_hash(p, request.form['password']):
                session['logged_in'] = True
                if a == 1:
                    session['admin'] = a
                return render_template('splash.html')
            else:
                error = "Incorrect password"
                return render_template('login.html', error=error)
    return render_template('login.html', error=error)


# Check to see if the username and password are valid
def check_password(username: str):
    """Check the passwords."""

    with DBcm.UseDatabase(DBconfig) as cursor:
        _SQL = "select * from user where (username = '%s')" % username
        cursor.execute(_SQL)
        return cursor.fetchone()


app.secret_key = "thisisasecret"

# start the server with the 'run()' method
if __name__ == '__main__':
    app.run(debug=True)
