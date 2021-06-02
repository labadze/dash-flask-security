# Flask package with dash

This application contains dash UI and python security mechanisms.

If you ask me I don't like out of the box solutions, but required and done picture is bellow.

## Features

Here are features which is minimalistic but ready for real life:

 - User can register on application using email
 - User gave to confirm account, only after that user can log in
 - User can recover and reset password
 - User can log in for sure
 - User can change password
 - User can log out

### How to run

 - Clone repo
 - Then create venv and install requirements
 - Do flask migrations `flask db init` read more at [https://flask-migrate.readthedocs.io/en/latest/](https://flask-migrate.readthedocs.io/en/latest/)
 - Setup envs to make emails works
 - Run application  `python -m flask run`
 - Open page on [http://127.0.0.1:5000](http://127.0.0.1:5000)
 - Use

### File / Folder structure


 - .gitignore
 - app.py 
 - identifier.sqlite
 - init_db.py
 - readme.md
 - requirements.txt

### Installed packages

    alembic==1.6.5
    Babel==2.9.1
    bcrypt==3.2.0
    blinker==1.4
    Brotli==1.0.9
    cffi==1.14.5
    click==8.0.1
    cryptography==3.4.7
    dash==1.20.0
    dash-core-components==1.16.0
    dash-html-components==1.1.3
    dash-renderer==1.9.1
    dash-table==4.11.3
    Flask==2.0.1
    Flask-BabelEx==0.9.4
    Flask-Compress==1.9.0
    Flask-Login==0.5.0
    Flask-Mail==0.9.1
    Flask-Migrate==3.0.1
    Flask-Principal==0.4.0
    Flask-Security==3.0.0
    Flask-SQLAlchemy==2.5.1
    Flask-WTF==0.15.1
    future==0.18.2
    greenlet==1.1.0
    itsdangerous==2.0.1
    Jinja2==3.0.1
    Mako==1.1.4
    MarkupSafe==2.0.1
    passlib==1.7.4
    plotly==4.14.3
    pycparser==2.20
    PyJWT==2.1.0
    python-dateutil==2.8.1
    python-dotenv==0.17.1
    python-editor==1.0.4
    pytz==2021.1
    retrying==1.3.3
    six==1.16.0
    speaklater==1.3
    SQLAlchemy==1.4.17
    Werkzeug==2.0.1
    WTForms==2.3.3

   

### What is used

During development was used flask security components, 

but in most operation, there was implemented native python features to make less additional packages depended.

 - Flask Login
 - Flask Mail
 - pyJWT
 - Dash
 - Bcrypt
 - Flask migrations
 - SQLITE

 You can view all packages in requirements file

### How it works

Because Sqlite it was decided to make application more depended on logic and cryptography, also on time frames instead on database entries.

So this is why it's very small and simple only one user's table with following params which are adopted for any database engine including firebase.

In a table I don't use integer as ID - this makes problem on big clusters.

    - id: uuid
    - email: string
    - password: string
    - activated_at: string(date_time) iso format by default it's null

#### Registration

User provides email on registration page, 

if user exists in database user receives notification if not, flask mail send confirmation URL and generated password

to provided email.

        - Important is how I generate confirmation URIL and how I verify user.
        Confirmation URL contains user id and email inside, in fact it's json web token 
        which contains this information.
        So here we have two benefits this token life time is only 30 minutes, after that
        Verification link expires.
        User information is encrypted inside and can be compared with user data in database. 
        Final question is how we accepting this token - Simple we have another parameter this is hashed email
        Which is compared with token sub vias bcrypt.

So once hashed email and token defined in query params and verification process is passed. We're sending informational email to user.


#### Recover and reset password

During recover password activated account is required. 

Service Messages like User not found, User not activated will be displayed.

For password recovery reset we're using not only token as URL we're using confirmation code, 

which is implemented inside token.

After token decoding, if email and confirmation code matches and token is not expired 

we're generating new password, setting it to database adn sending via email.

#### Change password

This function is available only for authorized users.

Process contains 2 steps: Change password init and change password commit.

        - On change password init we're generating 6 digit confirmation code
        Send it to email only after this action if authorized with current user password.
        Once confirmation code was sent we're redirectng user to change password commit page
        where user have to provide confirmation code, new password and new password again.
        After submit user will be  logged aut.
        To change password commit there will be passed encrypted confirmaton code to compare
        with provided and code lifetime which is base64 encrypted to make sure that change password
        code will not be used after 20 years :)

### Local environments

Here is list of envs which are required for application:

    SECRET_KEY=secret for flask security
    JWT_SECRET=secret for jwt
    MAIL_SERVER=smtp.some host here
    MAIL_PORT= integer
    MAIL_USE_TLS=True or False
    MAIL_USE_SSL=False or True
    MAIL_DEBUG=server.debug if needed
    MAIL_USERNAME=in most cases email address
    MAIL_PASSWORD=password
    MAIL_DEFAULT_SENDER=in most cases email
    MAIL_MAX_EMAILS=1000 or other if needed
    MAIL_SUPPRESS_SEND=server.testing for testing if needed
    MAIL_ASCII_ATTACHMENTS=True if you need attachments
    APP_URL=http://127.0.0.1:5000 ulr of application

In Windows systems use SET in unix export

NOTE every mail service has its own configuration.

### venv and local run

        
    - Create a project directory
    - Change into the project directory
    - Run python3 -m venv <name_of_virtualenv>

### Install packages

    pip install -r requirements.txt

## UI

There is very basic but structured UI there are W3.CSS implemented to make it responsive.

### What I want to implement but there is short timeframe

 - Send verification code to telegram
 - Do some user management interface
 - Define random email sender to prevent email blocks
 - Track more error and display

### Conclusion

IF you request feature I can implement requested without problems. Time by times I'll push some modifications 

ti branch feature(s)
