import os
from flask import Flask, redirect, url_for, session, request
from requests_oauthlib import OAuth2Session

# 🚀 Fix for HTTP in local development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Flask app configuration
app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secret key for sessions

# Google OAuth config
from flask import Flask, redirect, url_for, session, request
from requests_oauthlib import OAuth2Session
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Flask app configuration
app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secret key for sessions

# Google OAuth config
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI")

SCOPE = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/userinfo.email"
]
AUTHORIZATION_BASE_URL = "https://accounts.google.com/o/oauth2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
USER_INFO_URL = "https://www.googleapis.com/oauth2/v1/userinfo"

@app.route('/')
def home():
    return '<a href="/login">Login with Google</a>'

@app.route('/login')
def login():
    google = OAuth2Session(CLIENT_ID, scope=SCOPE, redirect_uri=REDIRECT_URI)
    auth_url, _ = google.authorization_url(AUTHORIZATION_BASE_URL, access_type="offline", prompt="consent")
    return redirect(auth_url)

@app.route('/callback')
def callback():
    google = OAuth2Session(CLIENT_ID, redirect_uri=REDIRECT_URI, scope=SCOPE)
    token = google.fetch_token(TOKEN_URL, client_secret=CLIENT_SECRET, authorization_response=request.url)
    session['oauth_token'] = token
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    if 'oauth_token' not in session:
        return redirect(url_for('login'))
    google = OAuth2Session(CLIENT_ID, token=session['oauth_token'])
    user_info = google.get(USER_INFO_URL).json()
    return f"Welcome {user_info['name']}! <br> <a href='/logout'>Logout</a>"

@app.route('/logout')
def logout():
    session.pop('oauth_token', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
