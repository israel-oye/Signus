import os, json, requests
from dotenv import load_dotenv
from oauthlib.oauth2 import WebApplicationClient
from flask import Flask, flash, render_template, request, url_for, redirect
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from models import User, db

load_dotenv()

app = Flask(__name__)
login_manager = LoginManager()

app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///signus.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", None)
GOOGLE_CLIENT_SECRET = os.getenv("CLIENT_SECRET", None)
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

db.init_app(app)
login_manager.init_app(app)

with app.app_context():
    db.create_all()

client = WebApplicationClient(GOOGLE_CLIENT_ID)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

@app.route("/", methods=['GET'])
def index():
    return render_template("index.html")

@app.route("/profile", methods=['GET'])
@login_required
def profile():
    if current_user.is_authenticated:
        app.logger.info(current_user.is_authenticated)
        return render_template("profile.html", user=current_user)
    else:
        app.logger.info(current_user.is_authenticated)
        return render_template("login.html")
    

@app.route("/login", methods=['GET', 'POST'])
def login():

    if request.method == 'GET':
        return render_template("login.html")

    elif current_user.is_authenticated:
        return redirect(url_for('profile'))

    elif request.method == 'POST':
        u_email = request.form['email']
        password_candidate = request.form['password']

        user = User.query.filter_by(email=u_email).first()

        if user and user.check_password(password_candidate):
            login_user(user)
            return redirect(url_for('profile'))

    
        google_provider_cfg = get_google_provider_cfg()
        authorization_endpoint = google_provider_cfg['authorization_endpoint']

        request_uri = client.prepare_request_uri(
            authorization_endpoint,
            redirect_uri=request.base_url + "/callback",
            scope=["openid", "email", "profile"]
            )
        
        return redirect(request_uri)

@app.route("/login/callback", methods=['GET', 'POST'])
def callback():
    code = request.args.get("code")

    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg['token_endpoint']
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response = request.url,
        redirect_url= request.base_url,
        code = code
    )

    token_response = requests.post(
        url=token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET)
        )

    client.parse_request_body_response(json.dumps(token_response.json()))

    user_info_endpoint = google_provider_cfg['userinfo_endpoint']
    uri, headers, body = client.add_token(user_info_endpoint)
    user_info_response = requests.get(url=uri, headers=headers, data=body)

    # client.parse_request_body_response(json.dumps(user_info_response.json()))

    if user_info_response.json().get("email_verified"):
        response = user_info_response.json()
        # u_id = int(response['sub'])
        u_email = response['email']
        u_name = response['given_name']
    else:
        flash("User email not available or not verified by Google", 'danger')
        return redirect(url_for('index'))

    user = User.query.filter_by(email=u_email).first()
    if user is None:
        user = User(name=u_name, email=u_email)
        db.session.add(user)
        db.session.commit()

    login_user(user)

    return redirect(url_for('index'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user: 
            flash("Email is taken!", 'danger')
            return redirect(url_for('signup'))

        
        new_user = User(email=email, name=name)
        new_user.set_password(password)

        
        db.session.add(new_user)
        db.session.commit()

        flash("Sign up successfull", 'success')
        return redirect(url_for('profile')) 
    return render_template("signup.html")

# @app.route("/regular_login", methods=['GET', 'POST'])
# def r_login():
#     if current_user.is_authenticated:
#         return redirect(url_for('profile'))

#     if request.method == 'POST':
#         u_email = request.form['email']
#         password_candidate = request.form['password']

#         user = User.query.filter_by(email=u_email).first()

#         if user and user.check_password(password_candidate):
#             return redirect(url_for('index'))

#     return render_template("login.html")

@app.route("/logout", methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == "__main__":
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    app.run(ssl_context="adhoc")