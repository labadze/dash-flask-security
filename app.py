import base64
import datetime
from dotenv import load_dotenv
import os
import re
import secrets
import sqlite3
import string
import time
import uuid
from sqlite3 import Error
from urllib import parse

import bcrypt

import jwt

from random import randint

from dash.exceptions import PreventUpdate
from flask import Flask
from flask_login import login_user, LoginManager, UserMixin, logout_user, current_user

import dash
from dash.dependencies import Input, Output, State
import dash_core_components as dcc
import dash_html_components as html

# CREDIT: This code is copied from Dash official documentation:
# https://dash.plotly.com/urls

# Since we're adding callbacks to elements that don't exist in the app.layout,
# Dash will raise an exception to warn us that we might be
# doing something wrong.
# In this case, we're adding the elements through a callback, so we can ignore
# the exception.
# Exposing the Flask Server to enable configuring it for logging in
from flask_mail import Message, Mail

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

external_stylesheets = ['https://codepen.io/chriddyp/pen/bWLwgP.css', 'https://www.w3schools.com/w3css/4/w3.css']

server = Flask(__name__)
server.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app = dash.Dash(__name__, server=server,
                title='DarkEngine',
                update_title='Loading...',
                external_stylesheets=external_stylesheets,
                suppress_callback_exceptions=True)

# Updating the Flask Server configuration with Secret Key to encrypt the user session cookie
server.config.update(SECRET_KEY=os.getenv('SECRET_KEY'))
server.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///identifier.sqlite'

db = SQLAlchemy(server)
migrate = Migrate(server, db)


class Users(db.Model):
    id = db.Column(db.String(128), primary_key=True)
    email = db.Column(db.String(128))
    password = db.Column(db.String(512))
    activated_at = db.Column(db.String(128))


# Login manager object will be used to login / logout users
login_manager = LoginManager()
login_manager.init_app(server)
login_manager.login_view = '/login'

mail = Mail(server)

server.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
server.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
server.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
server.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
server.config['MAIL_USE_TLS'] = False
server.config['MAIL_USE_SSL'] = True


def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


# User data model. It has to have at least self.id as a minimum


class User(UserMixin):
    def __init__(self, user_id, email, password):
        self.id = user_id
        self.email = email
        self.password = password

    # @classmethod
    # def get_id(self):
    #     return (self.user_id)


@login_manager.user_loader
def load_user(user_id):
    """ This function loads the user by user id. Typically this looks up the user from a user database.
        We won't be registering or looking up users in this example, since we'll just login using LDAP server.
        So we'll simply return a User object with the passed in username.
    """
    conn = sqlite3.connect('identifier.sqlite')
    conn.row_factory = dict_factory
    curs = conn.cursor()
    curs.execute("SELECT * from users where id = (?)", [user_id])
    user = curs.fetchone()
    conn.close()
    if user is None:
        return None
    else:
        # print(user)
        # print('LOGIN MANAGER FOUND')
        return User(user_id=user_id, email=user["email"], password=user["password"])


# Checks if input string is email address
def is_input_email(value):
    if len(value.strip().lower().replace(" ", "")) > 7:
        return bool(
            re.match("^.+@(\[?)[a-zA-Z0-9-.]+.([a-zA-Z]{2,3}|[0-9]{1,3})(]?)$", value.strip().lower().replace(" ", "")))
    else:
        return False


# Finds user by email checks if user exists in database
def find_user_by_email(email_address):
    # print('CHECKING USER BY EMAIL')
    conn = sqlite3.connect('identifier.sqlite')
    conn.row_factory = dict_factory
    curs = conn.cursor()
    curs.execute("SELECT * from users where email = (?)", [email_address.strip().lower().replace(" ", "")])
    user = curs.fetchone()
    conn.close()
    return user


def find_user_by_id(user_id):
    conn = sqlite3.connect('identifier.sqlite')
    conn.row_factory = dict_factory
    curs = conn.cursor()
    curs.execute("SELECT * from users where id = (?)", [user_id])
    user = curs.fetchone()
    conn.close()
    return user


# Creates new user on registration
def create_new_user(email_address):
    password = generate_new_password()
    hashed_password = hash_string(password)
    conn = sqlite3.connect('identifier.sqlite')
    conn.row_factory = dict_factory
    user_id = str(uuid.uuid4())
    try:
        conn = sqlite3.connect('identifier.sqlite')
    except Error as e:
        print(e)
    values = (user_id, email_address.strip().lower().replace(" ", ""), hashed_password.decode('utf-8'), None)
    sql = "INSERT INTO users (id, email, password, activated_at) VALUES(?,?,?,?)"
    curs = conn.cursor()
    curs.execute(sql, values)
    conn.commit()
    conn.close()
    verification_token = generate_account_confirmation_token(
        email_address=email_address.strip().lower().replace(" ", ""), user_id=user_id)
    hashed_email = hash_string(email_address)
    send_email_with_account_verification_link(email_address=email_address.strip().lower().replace(" ", ""),
                                              hashed_email=hashed_email, token=verification_token, password=password)


# Generates 6 digit verification code
def generate_verification_code():
    code = randint(100000, 999999)  # randint is inclusive at both ends
    return str(code)


# Generates token to reset password
def generate_reset_password_token(electric_mail, user_id, confirmation_code):
    secret = os.getenv("JWT_SECRET")
    encoded = jwt.encode({
        "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=900),
        # "nbf": datetime.datetime.utcnow() + datetime.timedelta(seconds=30),
        "iss": "DarkEngine",
        "aud": ['purpose:reset_password'],
        "sub": {"email": electric_mail, "code": confirmation_code, "user_id": user_id},
        "iat": datetime.datetime.utcnow()
    }, key=secret, algorithm="HS256",
        headers={"kid": str(uuid.uuid5(uuid.NAMESPACE_DNS, electric_mail))})
    return encoded


# Generates token to pass it in url and confirm account
def generate_account_confirmation_token(email_address, user_id):
    phrase = os.getenv('JWT_SECRET')
    encoded = jwt.encode({
        "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=900),
        # "nbf": datetime.datetime.utcnow() + datetime.timedelta(seconds=30),
        "iss": "DarkEngine",
        "aud": ['purpose:activate_account'],
        "sub": {"email": email_address, "user_id": user_id},
        "iat": datetime.datetime.utcnow()
    }, key=phrase,
        algorithm="HS256",
        headers={"kid": str(uuid.uuid5(uuid.NAMESPACE_DNS, email_address))})
    return encoded


# Can hash email to pass it to url or password
def hash_string(value):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(bytes(value, encoding="utf-8"), salt)
    return hashed


#  Generates new secured password
def generate_new_password():
    # secure random string
    # secure_str = ''.join((secrets.choice(string.ascii_letters) for i in range(8)))
    # print(secure_str)
    # Output QQkABLyK

    # secure password
    password = ''.join((secrets.choice(string.ascii_letters + string.digits + string.punctuation) for i in range(8)))
    # print(password)
    # output 4x]>@;4)
    return password


def decode_artifacts_for_reset_password(electric_mail, token, code):
    # first check if token is no expired
    # Then define if it's not before
    # After check issuer
    # Extract aud verification code and email
    # Compare if provided encrypted email is same as in sub
    # check that code in sub is same as provided 6 digit code
    phrase = os.getenv('JWT_SECRET')
    try:
        decoded = jwt.decode(token, key=str(phrase), issuer="DarkEngine", audience=['purpose:reset_password'],
                             algorithms=["HS256"])
        # print(decoded)
        if bcrypt.checkpw(password=decoded["sub"]["email"].encode(), hashed_password=electric_mail.encode()):
            # print('Email === hashed email')
            # print(decoded["sub"]["code"])
            if str(decoded["sub"]["code"]) == str(code):
                # print('Code is OK')
                if not decoded["sub"]["user_id"]:
                    return False
                else:
                    # print('USER FOUND')
                    user_id = decoded["sub"]["user_id"]
                    new_password = generate_new_password()
                    # print(new_password)
                    hashed_password = hash_string(new_password)
                    update_password_in_db(user_id=user_id, new_password=hashed_password)
                    send_email_reset_password(email=decoded["sub"]["email"], new_password=new_password)
                    return True
            else:
                return False
        else:
            return False
    except BaseException as e:
        print(e)
        return False


def decode_artifacts_for_account_verification(electric_mail, token):
    # decoded = jwt.decode(token, options={"require": ["exp", "iss", "sub"]})
    # print('START ACCOUNT VERIFICATION')
    phrase = os.getenv('JWT_SECRET')
    # print(phrase)
    try:
        decoded = jwt.decode(token, key=str(phrase), issuer="DarkEngine", audience=['purpose:activate_account'],
                             algorithms=["HS256"]
                             )
        # artifact = json.dumps(decoded)
        # print(decoded)
        # for key, value in decoded.items():
        # print(key)
        # print(value)

        if bcrypt.checkpw(password=decoded["sub"]["email"].encode(), hashed_password=electric_mail.encode()):
            activate_user_in_database(decoded["sub"]["user_id"])
            send_email_after_account_activation(decoded["sub"]["email"])
            return True
        else:
            return False
    except BaseException as e:
        print(e)
        return False


# Activate user in database
def activate_user_in_database(user_id):
    conn = sqlite3.connect('identifier.sqlite')
    conn.row_factory = dict_factory
    try:
        conn = sqlite3.connect('identifier.sqlite')
    except Error as e:
        print(e)
    values = (datetime.datetime.now().isoformat(), user_id)
    sql = "UPDATE users SET activated_at=? WHERE id=?"
    curs = conn.cursor()
    curs.execute(sql, values)
    conn.commit()
    conn.close()


# Sets new password for provided user id
def update_password_in_db(user_id, new_password):
    conn = sqlite3.connect('identifier.sqlite')
    conn.row_factory = dict_factory
    try:
        conn = sqlite3.connect('identifier.sqlite')
    except Error as e:
        print(e)
    values = (new_password.decode('utf-8'), user_id)
    sql = "UPDATE users SET password=? WHERE id=?"
    curs = conn.cursor()
    curs.execute(sql, values)
    conn.commit()
    conn.close()


# Checks if provided and hashed passwords match
def is_password_valid(password, hashed_password):
    if bcrypt.checkpw(password=password.encode(), hashed_password=hashed_password.encode()):
        return True
    else:
        return False


# Send email with recover / reset password link and security code
def send_email_recover_password(email, hashed_email, token, code):
    app_url = os.getenv('APP_URL')
    sender = os.getenv('MAIL_USERNAME')
    reset_url = app_url + '/reset_password?electric_mail=' + hashed_email.decode('utf-8') + '&token=' + token
    msg = Message(subject="Recover password", sender=sender, recipients=[email],
                  body='You request recover your password. We cannot remind your current password, because you are '
                       'only person who knows password even system keeps your password encrypted. But we can help you '
                       'to reset you password. To reset password please follow link ' + reset_url + ' and use '
                                                                                                    'following code: '
                       + code + ' Code is valid for 30 minutes.')
    try:
        mail.send(msg)
        return True
    except BaseException as e:
        print(e)
        return False


# Send email with new password after password reset procedure
def send_email_reset_password(email, new_password):
    sender = os.getenv('MAIL_USERNAME')
    msg = Message(subject="Reset password", sender=sender, recipients=[email],
                  body='Your new password is : ' + new_password +
                       ' Please change is as soon as possible')
    try:
        mail.send(msg)
        return True
    except BaseException as e:
        print(e)
        return False


# Sends user email with verification link and password for account
def send_email_with_account_verification_link(email_address, hashed_email, token, password):
    app_url = os.getenv('APP_URL')
    email_sender = os.getenv('MAIL_USERNAME')
    confirmation_url = app_url + '/activate_account?electric_mail=' + hashed_email.decode('utf-8') + '&token=' + token
    msg = Message(subject="Welcome", sender=email_sender, recipients=[email_address],
                  body='Welcome, you registered on website ' + app_url + '.  We\'re glad to see you here. One step '
                                                                         'left it\'s your account confirmation. '
                                                                         '\nPlease follow link ' + confirmation_url +
                       ' bellow to confirm your '
                       'account. You can log in to your account '
                       'after confirmation using password ' +
                       password + ' Have a nice day.')
    try:
        mail.send(msg)
        return True
    except BaseException as e:
        print(e)
        return False


# Send user email after account activation
def send_email_after_account_activation(email_address):
    app_url = os.getenv('APP_URL')
    sender = os.getenv('MAIL_USERNAME')
    msg = Message(subject="Your account is activated", sender=sender, recipients=[email_address],
                  body='Welcome, you registered on website ' + app_url + '.  '
                                                                         'Now your account is activated. You can '
                                                                         'log in using your ' + email_address + ' and'
                                                                                                                'password. Thank you.')
    try:
        mail.send(msg)
        return True
    except BaseException as e:
        print(e)
        return False


# Send verification code to change password
# Send user email after account activation
def send_email_with_verification_code_to_change_password(email_address, code):
    app_url = os.getenv('APP_URL')
    sender = os.getenv('MAIL_USERNAME')
    msg = Message(subject="Change password verification", sender=sender, recipients=[email_address],
                  body='Hello, you\'re receiving this email because you decided to change password on app ' + app_url + '.  '
                                                                                                                        'Your password change request was authorized, so to complete password change procedure you need verify it with code  '
                                                                                                                        '' + code + ' do not share this code to someone else.')
    try:
        mail.send(msg)
        return True
    except BaseException as e:
        print(e)
        return False


# User status management views

# Login screen
register = html.Div([dcc.Location(id='register', refresh=True),
                     html.H2('''Create new account:''', className='w3-center', id='h1'),
                     html.Br(),
                     html.Div(children='', id='output-state-register',
                              # style={'width': '40%'},
                              className='w3-center'),
                     html.Br(),
                     html.Div([
                         dcc.Input(placeholder='Enter your email',
                                   type='email', id='register-email-box'),
                     ], className='w3-center'),

                     html.Br(),
                     html.Div([
                         html.Button(children='Register', n_clicks=0,
                                     type='submit', id='register-button'),
                     ], className='w3-center'),
                     html.Br(),
                     html.Div([
                         dcc.Link('Login', href='/login'),
                     ], className='w3-center'),
                     html.Br(),
                     html.Br(),
                     dcc.Link('Home', href='/')])

# Login screen
login = html.Div([dcc.Location(id='url_login', refresh=True),
                  html.H2('''Please log in to continue:''', className='w3-center', id='h1'),
                  html.Br(),
                  html.Div(children='', id='output-state',
                           # style={'width': '40%'},
                           className='w3-center'),
                  html.Br(),
                  html.Div([
                      dcc.Input(placeholder='Enter your email',
                                type='email', id='email-box'),
                  ], className='w3-center'),

                  html.Br(),
                  html.Div([
                      dcc.Input(placeholder='Enter your password',
                                type='password', id='pwd-box'),
                  ], className='w3-center'),
                  html.Br(),
                  html.Div([
                      html.Button(children='Login', n_clicks=0,
                                  type='submit', id='login-button'),
                  ], className='w3-center'),
                  html.Br(),
                  html.Div([
                      dcc.Link('Recover password', href='/recover-password'),
                  ], className='w3-center'),
                  html.Br(),
                  html.Div([
                      dcc.Link('Register', href='/register'),
                  ], className='w3-center'),
                  html.Br(),
                  html.Br(),
                  dcc.Link('Home', href='/')])

# Successful login
success = html.Div([html.Div([html.H2('Login successful.'),
                              html.Br(),
                              dcc.Link('Home', href='/')])  # end div
                    ])  # end div

# Successful login
success_public_operations = html.Div([html.Div([html.H2('Operation success.', className='w3-center'),
                                                html.Br(),
                                                dcc.Link('Home', href='/', className='w3-center')])  # end div
                                      ])  # end div

# Failed Login
failed = html.Div([html.Div([html.H2('Log in Failed. Please try again.'),
                             html.Br(),
                             html.Div([login]),
                             dcc.Link('Home', href='/')
                             ])  # end div
                   ])  # end div

# Recover password
recover_password = html.Div([dcc.Location(id='recover-password', refresh=True),
                             html.H2('''Please provide your email:''', id='h1', className='w3-center'),
                             html.Br(),
                             html.Div(children='', id='output-state-for-recover-password', className='w3-center'),
                             html.Br(),
                             html.Div([
                                 dcc.Input(placeholder='Enter your email',
                                           type='email', id='email-box'),
                             ], className='w3-center'),
                             html.Br(),
                             html.Div([
                                 html.Button(children='recover-password', n_clicks=0,
                                             type='submit', id='recover-password-button'),
                             ], className='w3-center'),
                             html.Br(),
                             html.Br(),
                             dcc.Link('Login', href='/login', className='w3-center'),
                             html.Br(),
                             dcc.Link('Home', href='/')], className='w3-center')

# Reset password
reset_password = html.Div([dcc.Location(id='reset_password', refresh=True),
                           html.H2('''Please provide confirmation code:''', id='h1', className='w3-center'),
                           html.Br(),
                           html.Div([
                               dcc.Input(placeholder='6 Digit Code',
                                         type='number', id='code-box'),
                           ], className='w3-center'),
                           html.Br(),
                           html.Div([
                               html.Button(children='reset password', n_clicks=0,
                                           type='submit', id='reset-password-button'),
                           ], className='w3-center'),
                           html.Br(),
                           html.Div(children='', id='output-state-for-reset-password', className='w3-center'),
                           html.Br(),
                           dcc.Link('Login', href='/login', className='w3-center'),
                           html.Br(),
                           dcc.Link('Home', href='/')], className='w3-center')

# logout
logout = html.Div([html.Div(html.H2('You have been logged out - Please login')),
                   html.Br(),
                   dcc.Link('Home', href='/')
                   ])  # end div

activate_account = html.Div([dcc.Location(id='activate_account', refresh=True),
                             # dcc.Location(id='activate_account_path'),
                             html.H1('Account Activation', className='w3-center'),
                             html.Br(),
                             html.Div(children='', id='output-state-for-activate-account',
                                      # style={'width': '40%'},
                                      className='w3-center'),
                             html.Br(),
                             html.Div([
                                 dcc.Link('Go to Login page', href='/login'),
                             ], className='w3-center'),

                             html.Br(),

                             html.Div([
                                 dcc.Link('Go back to home', href='/'),
                             ], className='w3-center'),
                             ])

# Start change password
change_password_initiate = html.Div([dcc.Location(id='recover-password', refresh=True),
                                     html.H2('''Please provide your current password:''', id='h1',
                                             className='w3-center'),
                                     html.Br(),
                                     html.Div(children='', id='output-state-for-change-password-init',
                                              className='w3-center'),
                                     html.Br(),
                                     html.Div([
                                         dcc.Input(placeholder='Current password',
                                                   type='password', id='current-password-box'),
                                     ], className='w3-center'),
                                     html.Br(),
                                     html.Div([
                                         html.Button(children='Authorize', n_clicks=0,
                                                     type='submit', id='change-password-init-button'),
                                     ], className='w3-center'),
                                     html.Br(),
                                     html.Br(),
                                     dcc.Link('Login', href='/login', className='w3-center'),
                                     html.Br(),
                                     dcc.Link('Home', href='/')], className='w3-center')


# Callback function to login the user, or update the screen if the username or password are incorrect
@app.callback(
    Output('url_login', 'pathname'), Output('output-state', 'children'), [Input('login-button', 'n_clicks')],
    [State('email-box', 'value'), State('pwd-box', 'value')])
def login_button_click(n_clicks, email, password):
    if n_clicks == 0:
        raise PreventUpdate
    else:
        if not email:
            return '/login', 'Email was not provided'
        elif not is_input_email(email):
            return '/login', 'Email format is not correct'
        elif not password:
            return '/login', 'Please enter your password'
        else:
            usr = find_user_by_email(email)
            if usr is not None:
                if bcrypt.checkpw(password=password.encode(), hashed_password=usr["password"].encode()):
                    user = User(user_id=usr["id"], email=usr["email"], password=usr["password"])
                    login_user(user)
                    return '/success', ''
                else:
                    return '/login', 'Incorrect password'
            else:
                return '/login', 'User not found'


# Callback provides registration process
@app.callback(
    Output('register', 'pathname'), Output('output-state-register', 'children'),
    [Input('register-button', 'n_clicks')],
    [State('register-email-box', 'value')])
def register_button_click(n_clicks, email):
    if n_clicks == 0:
        raise PreventUpdate
    else:
        if not email:
            return '/register', 'Email was not provided'
        elif not is_input_email(email):
            return '/register', 'Email format is not correct'
        usr = find_user_by_email(email)
        if usr is None:
            create_new_user(email)
            return '/cmd_success', 'Registration successful, please check your email to verify your account.'
        else:
            return '/register', 'User is already exists please log in'


# Callback provides account activation process
@app.callback(
    Output('activate_account', 'pathname'),
    Output('output-state-for-activate-account', 'children'),
    [Input('url', 'search')])
def account_activation(search):
    query = parse.parse_qs(parse.urlparse(search).query)
    # print({k: v[0] if v and len(v) == 1 else v for k, v in query.items()})
    result = {k: v[0] if v and len(v) == 1 else v for k, v in query.items()}
    if result is None:
        return '/activate_account', 'Cannot complete your request...'
    elif 'electric_mail' not in result or 'token' not in result:
        return '/activate_account', 'We cannot activate user...'
    elif not result["electric_mail"]:
        return '/activate_account', 'Undetected user...'
    elif not result["token"]:
        return '/activate_account', 'Missing token ...'
    else:
        check_d = decode_artifacts_for_account_verification(electric_mail=result["electric_mail"],
                                                            token=result["token"])
        if check_d is True:
            return '/activate_account', 'Your account successfully activated'
        else:
            return '/activate_account', 'Activation URL is expired or already used or broken contact administrator or ' \
                                        'request another activation URL from your email '


# Callback provides reset password process
@app.callback(
    Output('reset_password', 'pathname'),
    Output('output-state-for-reset-password', 'children'),
    [Input('reset-password-button', 'n_clicks')],
    [Input('url', 'search')],
    [State('code-box', 'value')])
def reset_user_password(n_clicks, search, code):
    # ctx = dash.callback_context
    # print(ctx.triggered[0])
    # print(code)
    query = parse.parse_qs(parse.urlparse(search).query)
    result = {k: v[0] if v and len(v) == 1 else v for k, v in query.items()}
    if n_clicks == 0 and not code:
        raise PreventUpdate
    else:
        if result is not None:
            if 'electric_mail' not in result or 'token' not in result:
                return '/reset_password', 'We cannot activate user...'
            elif not result["electric_mail"]:
                return '/reset_password', 'Undetected user...'
            elif not result["token"]:
                return '/reset_password', 'Missing token ...'
            else:
                if n_clicks > 0:
                    if not code:
                        return '/reset_password', 'Please provide Code.'
                    else:
                        if decode_artifacts_for_reset_password(electric_mail=result["electric_mail"],
                                                               token=result["token"], code=code) is True:
                            return '/cmd_success', 'Your password was reset, please check your email for new password '
                        else:
                            return '/reset_password', 'We Complete your request: Activation link is broken, request ' \
                                                      'one more using ' \
                                                      'your email. '
        else:
            return '/reset_password', 'We Complete your request: Activation link is broken, request one more using ' \
                                      'your email. '


# Recover password callback
@app.callback(
    Output('recover-password', 'pathname'),
    Output('output-state-for-recover-password', 'children'),
    [Input('recover-password-button', 'n_clicks')],
    [State('email-box', 'value')])
def recover_password_button_click(n_clicks, electric_mail):
    if n_clicks == 0:
        raise PreventUpdate
    else:
        if not electric_mail:
            return '/recover-password', 'Please provide Email.'
        elif is_input_email(electric_mail) is False:
            return '/recover-password', 'Email is not in correct format...'
        else:
            usr = find_user_by_email(electric_mail)
        if usr is not None:
            if usr["activated_at"] is None:
                return '/recover-password', 'you need to activate user to recover your password.'
            else:
                confirmation_code = generate_verification_code()
                token = generate_reset_password_token(electric_mail=usr["email"], user_id=usr["id"],
                                                      confirmation_code=confirmation_code)
                hashed_electric_mail = hash_string(electric_mail.strip().lower().replace(" ", ""))

                send_email_recover_password(email=electric_mail.strip().lower().replace(" ", ""),
                                            hashed_email=hashed_electric_mail, token=token,
                                            code=confirmation_code)
                return '/cmd_success', 'Recover password link was sent to your email ' + electric_mail


# Callback provides change password initiate process
@app.callback(
    Output('change_password_init', 'pathname'),
    Output('output-state-for-change-password-init', 'children'),
    [Input('change-password-init-button', 'n_clicks')],
    [State('current-password-box', 'value')])
def change_password_init_button_click(n_clicks, current_password):
    if n_clicks == 0:
        raise PreventUpdate
    else:
        if not current_password:
            return '/change_password_init', 'Current password was not provided'
        usr = find_user_by_id(current_user.get_id())
        if usr is None:
            logout_user()
            return '/change_password_init', 'User was not detected'
        else:
            if is_password_valid(password=current_password, hashed_password=usr["password"]) is True:
                # Generate confirmation code
                confirmation_code = generate_verification_code()
                # Send confirmation code
                send_email_with_verification_code_to_change_password(email_address=usr["email"], code=confirmation_code)
                # Encrypt confirmation code to pass to next page
                encrypted_code = hash_string(confirmation_code)
                # Encode expiration unix timestamp and pass
                expiration_ts = round(time.time() * 1000)
                exp_bytes = str(expiration_ts).encode('utf-8')
                base64_bytes = base64.b64encode(exp_bytes)
                base64_message = base64_bytes.decode('utf-8')
                # Redirect to change password commit page
                return '/change_password_commit?c=' + encrypted_code.decode(
                    'utf-8') + '&exp=' + base64_message, 'Now provide verification code, new password and new password ' \
                                                         'confirmation '


# TODO: complete change password
# Callback provides change password initiate process
@app.callback(
    Output('change_password_commit', 'pathname'),
    Output('output-state-for-change-password-commit', 'children'),
    [Input('change-password-commit-button', 'n_clicks')],
    [State('current-password-box', 'value')])
def change_password_init_button_click(n_clicks, current_password):
    if n_clicks == 0:
        raise PreventUpdate
    else:
        if not current_password:
            return '/change_password_init', 'Current password was not provided'
        usr = find_user_by_id(current_user.get_id())
        if usr is None:
            logout_user()
            return '/change_password_init', 'User was not detected'
        else:
            if is_password_valid(password=current_password, hashed_password=usr["password"]) is True:
                # Generate confirmation code
                confirmation_code = generate_verification_code()
                # Send confirmation code
                send_email_with_verification_code_to_change_password(email_address=usr["email"], code=confirmation_code)
                # Redirect to change password commit page
                return '/change_password_commit', 'Now provide verification code, new password and new password confirmation'


# Main Layout
app.layout = html.Div([
    dcc.Location(id='url', refresh=False),
    dcc.Location(id='redirect', refresh=True),
    dcc.Store(id='login-status', storage_type='session'),
    html.Div(id='user-status-div'),
    html.Br(),
    html.Hr(),
    html.Br(),
    html.Div(id='page-content'),
], className='w3-center w3-content')

index_page = html.Div([
    dcc.Link('Go to Page 1', href='/page-1'),
    html.Br(),
    dcc.Link('Go to Page 2', href='/page-2'),
])

page_1_layout = html.Div([
    html.H1('Page 1'),
    dcc.Dropdown(
        id='page-1-dropdown',
        options=[{'label': i, 'value': i} for i in ['LA', 'NYC', 'MTL']],
        value='LA'
    ),
    html.Div(id='page-1-content'),
    html.Br(),
    dcc.Link('Go to Page 2', href='/page-2'),
    html.Br(),
    dcc.Link('Go back to home', href='/'),
])


@app.callback(Output('page-1-content', 'children'), [Input('page-1-dropdown', 'value')])
def page_1_dropdown(value):
    return 'You have selected "{}"'.format(value)


page_2_layout = html.Div([
    html.H1('Page 2'),
    dcc.RadioItems(
        id='page-2-radios',
        options=[{'label': i, 'value': i} for i in ['Orange', 'Blue', 'Red']],
        value='Orange'
    ),
    html.Div(id='page-2-content'),
    html.Br(),
    dcc.Link('Go to Page 1', href='/page-1'),
    html.Br(),
    dcc.Link('Go back to home', href='/')
])


@app.callback(Output('page-2-content', 'children'), [Input('page-2-radios', 'value')])
def page_2_radios(value):
    return 'You have selected "{}"'.format(value)


@app.callback(Output('user-status-div', 'children'), Output('login-status', 'data'), [Input('url', 'pathname')])
def login_status(url):
    ''' callback to display login/logout link in the header '''
    if hasattr(current_user, 'is_authenticated') and current_user.is_authenticated \
            and url != '/logout':  # If the URL is /logout, then the user is about to be logged out anyways
        return dcc.Link('logout', href='/logout'), current_user.get_id()
    else:
        return dcc.Link('login', href='/login'), 'Successfully signed out'


# Main router
@app.callback(Output('page-content', 'children'), Output('redirect', 'pathname'), [Input('url', 'pathname')])
def display_page(pathname):
    ''' callback to determine layout to return '''
    # We need to determine two things for everytime the user navigates: Can they access this page? If so,
    # we just return the view Otherwise, if they need to be authenticated first, we need to redirect them to the
    # login page So we have two outputs, the first is which view we'll return The second one is a redirection to
    # another page is needed In most cases, we won't need to redirect. Instead of having to return two variables
    # everytime in the if statement We setup the defaults at the beginning, with redirect to dash.no_update; which
    # simply means, just keep the requested url
    view = None
    url = dash.no_update
    if pathname == '/login':
        view = login
    elif pathname == '/register':
        view = register
        url = '/register'
    elif pathname == '/activate_account':
        view = activate_account
        url = '/activate_account'
    elif pathname == '/recover-password':
        view = recover_password
        url = '/recover-password'
    elif pathname == '/reset_password':
        view = reset_password
        url = '/reset_password'
    elif pathname == '/cmd_success':
        view = success_public_operations
        url = '/cmd_success'
    elif pathname == '/success':
        if current_user.is_authenticated:
            view = success
        else:
            view = failed
    elif pathname == '/logout':
        if current_user.is_authenticated:
            logout_user()
            view = logout
        else:
            view = login
            url = '/login'

    elif pathname == '/page-1':
        view = page_1_layout
    elif pathname == '/page-2':
        if current_user.is_authenticated:
            view = page_2_layout
        else:
            view = 'Redirecting to login...'
            url = '/login'
    elif pathname == '/change_password_init':
        if current_user.is_authenticated:
            view = change_password_initiate
        else:
            view = 'Redirecting to login...'
            url = '/login'
    else:
        view = index_page
    # You could also return a 404 "URL not found" page here
    return view, url


if __name__ == '__main__':
    load_dotenv()
    app.run_server(debug=True)
