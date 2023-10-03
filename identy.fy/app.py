from datetime import datetime, date, timedelta
import logging
import urllib.parse
import os
import time
import requests
import base64
from email_validator import validate_email, EmailNotValidError
from sqlalchemy import ForeignKey
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    jsonify,
    current_app,
)
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URI", "sqlite:///site.db"
)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "fallback_secret_key")
client_id = os.environ.get("SPOTIFY_CLIENT_ID")
client_secret = os.environ.get("SPOTIFY_CLIENT_SECRET")
db = SQLAlchemy(app)
migrate = Migrate(app, db)
logging.basicConfig(level=logging.DEBUG)


# Global error handler
@app.errorhandler(Exception)
def handle_exception(e):
    logging.error(f"Unhandled exception: {e}")
    flash("An unexpected error occurred. Please try again later.", "danger")
    return redirect(url_for("index"))


# Spotify API token
def get_token():
    auth_string = client_id + ":" + client_secret
    auth_bytes = auth_string.encode("utf-8")
    auth_b64_bytes = base64.b64encode(auth_bytes)

    url = "https://accounts.spotify.com/api/token"
    headers = {
        "Authorization": "Basic " + auth_b64_bytes.decode("utf-8"),
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {"grant_type": "client_credentials"}

    result = requests.post(url, headers=headers, data=data)

    result.raise_for_status()

    json_result = result.json()
    token = json_result["access_token"]
    logging.debug(f"Spotify token: {token}")

    return token


spotify_token = get_token()


# Common data for AUDD API requests
def get_common_data():
    api_token = os.environ.get("API_TOKEN", "default_token")
    logging.debug(f"API Token: {api_token}")
    return {
        "api_token": api_token,
        "accurate_offsets": "true",
        "skip": "30",
        "every": "1",
    }


# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    token = db.Column(db.String(200))
    spotify_name = db.Column(db.String(200), default="No account connected")
    refresh_token = db.Column(db.String(200))
    expiration_time = db.Column(db.DateTime)
    date_of_birth = db.Column(db.Date, nullable=False, default=date.today())
    password = db.Column(db.String(60), nullable=False)
    playlists = db.relationship(
        "Playlist", backref="user", lazy=True, cascade="all, delete-orphan"
    )


class Playlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    created_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    tracks = db.relationship(
        "Track", backref="playlist", lazy=True, cascade="all, delete-orphan"
    )
    user_id = db.Column(db.Integer, ForeignKey("user.id"), nullable=False)


class Track(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    artist = db.Column(db.String(100), nullable=False)
    album = db.Column(db.String(100), nullable=False)
    release_date = db.Column(db.Date, nullable=False, default=date(1900, 1, 1))
    song_link = db.Column(db.String(200))
    song_uri = db.Column(db.String(200))
    playlist_id = db.Column(db.Integer, ForeignKey("playlist.id"), nullable=False)


# Helper functions
def is_valid_date(date_str):
    """Check if the provided date string is a valid date and not in the future."""
    try:
        input_date = datetime.strptime(date_str, "%Y-%m-%d").date()
        if input_date > date.today():
            return False, "The date cannot be in the future."
        return True, ""
    except ValueError:
        return False, "Invalid date format. Please use YYYY-MM-DD."


def validate_user_input(username, password, email, dob):
    """Centralized validation for user input."""
    if not username or len(username) < 6:
        return False, "You must provide a username that is at least 6 characters"

    if not password or len(password) < 8:
        return False, "Your password must be at least 8 characters."

    try:
        v = validate_email(email)
    except EmailNotValidError:
        return False, "The email address is not valid. Please double-check it."

    return True, ""


# Routes
@app.route("/")
def index():
    if "user_id" in session:
        user = User.query.get(session["user_id"])
        if user:
            return render_template("index.html", username=user.username)
    return render_template("index.html", username=None)


# Upload routes
@app.route("/upload", methods=["GET", "POST"])
def upload():
    logging.info("Upload route accessed.")
    result = {"success": False, "message": "Invalid upload type"}
    if request.method == "POST":
        upload_type = request.form.get("uploadType")

        if upload_type == "file":
            result = handle_file_upload(request)
        elif upload_type == "url":
            result = handle_url_upload(request)

        if result["success"]:
            return redirect(url_for("playlists"))
        else:
            return redirect(url_for("upload"))

    return render_template("upload.html", upload_page_bg=True)


def handle_file_upload(request):
    file = request.files.get("file")

    if not file or file.filename == "":
        return {"success": False, "message": "Please make sure you upload a file."}

    if file.filename.split(".")[-1].lower() not in ["wav", "mp3"]:
        return {
            "success": False,
            "message": "Invalid file type, only WAV and MP3 are allowed.",
        }

    if file.content_length > (1 * 1024 * 1024 * 1024):
        return {"success": False, "message": "File size exceeds limit (1GB)."}

    files = {"file": (file.filename, file.stream)}
    response = requests.post(
        "https://enterprise.audd.io/", data=get_common_data(), files=files
    )
    logging.debug(f"API Response: {response.text}")
    process_response(response)

    if response.ok:
        return {"success": True, "message": "File has been processed successfully."}
    else:
        return {"success": False, "message": "Error processing the file."}


def handle_url_upload(request):
    url = request.form.get("url")

    if not url or url.strip() == "":
        return {"success": False, "message": "Please make sure you submit a URL."}

    flash("Processing started. This may take a few minutes.", "info")

    url_data = {"url": url}
    all_data = {**get_common_data(), **url_data}
    response = requests.post("https://enterprise.audd.io/", data=all_data)
    logging.debug(f"API Response: {response.text}")
    process_response(response)

    if response.ok:
        return {
            "success": True,
        }
    else:
        return {"success": False, "message": "Error processing the URL."}


def process_response(response):
    logging.debug("Entered process_response")
    user_id = session.get("user_id", None)
    if user_id is None:
        flash("You need to be logged in to create playlists", "danger")
        return redirect(url_for("login"))

    try:
        response_json = response.json()
        logging.debug(f"API response: {response_json}")
    except ValueError:
        flash("Invalid response from API", "danger")
        return redirect(url_for("playlists"))

    if response_json["status"] == "success":
        logging.debug("Status success, processing tracks")
        if not response_json["result"]:
            flash("No songs found in the file.", "danger")
            return redirect(url_for("playlists"))
        playlist_id = create_playlist(user_id)
        populate_playlist(playlist_id, response_json["result"])
        flash("Playlist Created Successfully!", "success")
    else:
        flash("Could not create playlist", "danger")
        logging.debug(f"Status not successful: {response_json['status']}")

    return redirect(url_for("playlists"))


# Playlist routes
def create_playlist(user_id):
    new_playlist = Playlist(name="New Playlist", user_id=user_id)
    db.session.add(new_playlist)
    db.session.commit()
    return new_playlist.id


def populate_playlist(playlist_id, results):
    unique_tracks = set()

    for result in results:
        for song in result.get("songs", []):
            release_date_str = song.get("release_date", "1900-01-01")
            track_name = song.get("title", "")
            release_date_obj = datetime.strptime(release_date_str, "%Y-%m-%d").date()

            track_link = song.get("song_link", "")
            uri = get_uri(song["title"], song["artist"], song["album"])
            if track_link or track_name or uri not in unique_tracks:
                new_track = Track(
                    title=song["title"],
                    artist=song["artist"],
                    album=song["album"],
                    release_date=release_date_obj,
                    song_link=song.get("song_link", ""),
                    playlist_id=playlist_id,
                    song_uri=uri,
                )
                try:
                    db.session.add(new_track)
                    unique_tracks.add(track_link)
                    db.session.commit()
                except Exception as e:
                    logging.error(f"Error adding track to database: {e}")
                    db.session.rollback()


MAX_RETRIES = 3


# Spotify routes
def get_uri(title, artist, album, retry_count=0):
    global spotify_token
    title_encoded = urllib.parse.quote(title)
    artist_encoded = urllib.parse.quote(artist)
    album_encoded = urllib.parse.quote(album)

    url = f"https://api.spotify.com/v1/search?q={title_encoded}+{artist_encoded}+{album_encoded}&type=track&limit=1"
    headers = {"Authorization": f"Bearer {spotify_token}"}
    response = requests.get(url, headers=headers)

    if response.status_code == 401 and retry_count < MAX_RETRIES:
        logging.info("Refreshing Spotify token")
        spotify_token = get_token()
        return get_uri(title, artist, album, retry_count + 1)
    elif response.status_code == 429:
        logging.warning("Rate limit exceeded on Spotify API")
        time.sleep(10)
        return None
    elif not response.ok:
        logging.error(f"Error {response.status_code}: {response.text}")
        return None
    else:
        response_json = response.json()
        if response_json.get("tracks", {}).get("items", []):
            return response_json["tracks"]["items"][0]["uri"]


@app.route("/spotify/auth")
def authorization():
    if "user_id" not in session:
        flash("You need to be logged in to access Spotify features", "danger")
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])
    user_token = user.token
    user_expiration = user.expiration_time
    current_time = datetime.now()
    if user_token and user_expiration > current_time:
        return redirect(url_for("playlists"))

    SPOTIFY_AUTH_URL = "https://accounts.spotify.com/authorize"
    REDIRECT_URI = "http://127.0.0.1:5000/callback"
    SCOPE = "user-read-private playlist-modify-public playlist-modify-private"

    auth_query_parameters = {
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
        "client_id": client_id,
    }

    url_args = "&".join(
        [
            "{}={}".format(key, urllib.parse.quote(val))
            for key, val in auth_query_parameters.items()
        ]
    )
    auth_url = "{}/?{}".format(SPOTIFY_AUTH_URL, url_args)
    return redirect(auth_url)


@app.route("/callback")
def callback():
    REDIRECT_URI = "http://127.0.0.1:5000/callback"
    auth_token = request.args.get("code")
    if not auth_token:
        flash("Authorization failed.", "danger")
        return redirect(url_for("playlists"))

    code_payload = {
        "grant_type": "authorization_code",
        "code": auth_token,
        "redirect_uri": REDIRECT_URI,
        "client_id": client_id,
        "client_secret": client_secret,
    }

    post_request = requests.post(
        "https://accounts.spotify.com/api/token", data=code_payload
    )

    if post_request.status_code != 200:
        flash("Failed to retrieve access token.", "danger")
        return redirect(url_for("playlists"))

    response_data = post_request.json()
    user_token = response_data.get("access_token")
    user_refresh_token = response_data.get("refresh_token")
    expires_in = response_data.get("expires_in")
    expiration_time = datetime.now() + timedelta(seconds=expires_in)
    headers = {"Authorization": f"Bearer {user_token}"}
    response = requests.get("https://api.spotify.com/v1/me", headers=headers)

    if response.status_code != 200:
        flash("Failed to retrieve Spotify user data.", "danger")
        return redirect(url_for("playlists"))

    spotify_user_data = response.json()

    user = User.query.get(session["user_id"])
    user.spotify_name = spotify_user_data.get("display_name")
    user.token = user_token
    user.refresh_token = user_refresh_token
    user.expiration_time = expiration_time
    db.session.commit()

    target_playlist_id = session.get("target_playlist_id")
    if target_playlist_id:
        session.pop("target_playlist_id", None)
        return redirect(
            url_for("create_spotify_playlist", playlist_id=target_playlist_id)
        )

    return redirect(url_for("playlists"))


@app.route("/create-spotify-playlist/<int:playlist_id>")
def create_spotify_playlist(playlist_id):
    user = User.query.get(session["user_id"])
    user_token = user.token
    user_expiration = user.expiration_time
    current_time = datetime.now()

    if not user_token or user_expiration <= current_time:
        session["target_playlist_id"] = playlist_id
        return redirect(url_for("authorization"))

    playlist_name = Playlist.query.get(playlist_id).name
    headers = {"Authorization": f"Bearer {user_token}"}

    response = requests.post(
        f"https://api.spotify.com/v1/me/playlists",
        headers=headers,
        json={
            "name": playlist_name,
            "public": False,
            "description": "Created by Identy.fy",
        },
    )
    if response.status_code != 201:
        flash("Failed to create Spotify playlist.", "danger")
        return redirect(url_for("playlists"))

    spotify_playlist_id = response.json()["id"]
    track_uris = [track.song_uri for track in Playlist.query.get(playlist_id).tracks]

    response = requests.post(
        f"https://api.spotify.com/v1/playlists/{spotify_playlist_id}/tracks",
        headers=headers,
        json={"uris": track_uris},
    )
    if response.status_code != 201:
        flash("Failed to add tracks to Spotify playlist.", "danger")
        return redirect(url_for("playlists"))

    flash("Playlist created successfully on Spotify!", "success")
    return redirect(url_for("playlists"))


# Playlist routes
@app.route("/playlists")
def playlists():
    if "user_id" not in session:
        flash("Please log in to view your playlists.", "danger")
        return redirect(url_for("login"))

    user_id = session["user_id"]
    playlists = Playlist.query.filter_by(user_id=user_id).all()
    return render_template("playlists.html", playlists=playlists)


@app.route("/delete-playlist/<int:playlist_id>", methods=["POST"])
def delete_playlist(playlist_id):
    playlist = Playlist.query.get_or_404(playlist_id)

    if playlist.user_id != session.get("user_id"):
        flash("You do not have permission to delete this playlist.", "danger")
        return jsonify(success=False)

    for track in playlist.tracks:
        db.session.delete(track)

    db.session.delete(playlist)
    db.session.commit()

    flash("Playlist deleted successfully.", "success")
    return jsonify(success=True)


@app.route("/delete-track/<int:track_id>", methods=["POST"])
def delete_track(track_id):
    track = Track.query.get_or_404(track_id)
    playlist = Playlist.query.get(track.playlist_id)

    if playlist.user_id != session.get("user_id"):
        flash("You do not have permission to delete this track.", "danger")
        return jsonify(success=False)

    db.session.delete(track)
    db.session.commit()

    flash("Track deleted successfully.", "success")
    return jsonify(success=True)


@app.route("/rename-playlist/<int:playlist_id>", methods=["POST"])
def rename_playlist(playlist_id):
    playlist = Playlist.query.get_or_404(playlist_id)

    if playlist.user_id != session.get("user_id"):
        flash("You do not have permission to rename this playlist.", "danger")
        return jsonify(success=False)

    new_name = request.form.get("new_name")
    playlist.name = new_name
    db.session.commit()

    return jsonify(success=True)


# Settings routes
@app.route("/settings", methods=["GET", "POST"])
def settings():
    user = User.query.get(session["user_id"])
    spotify_display_name = user.spotify_name
    if not user:
        flash("You need to login to see this page.", "danger")
        return redirect("/login")
    if request.method == "POST":
        action = request.form.get("action")
        if action == "change_password":
            old_password = request.form.get("old_password")
            new_password = request.form.get("new_password")
            confirm_password = request.form.get("confirm_password")
            if not check_password_hash(user.password, old_password):
                flash("Old password is incorrect.", "danger")
            elif new_password != confirm_password:
                flash("New password and confirmation do not match.", "danger")
            elif len(new_password) < 8:
                flash("Your password must be at least 8 characters.", "danger")
            else:
                user.password = generate_password_hash(new_password)
                db.session.commit()
                flash("Password changed successfully.", "success")
        if action == "change_email":
            new_email = request.form.get("new_email")
            password = request.form.get("password")
            dob = datetime.strptime(request.form.get("dob"), "%Y-%m-%d").date()
            dob_valid, dob_message = is_valid_date(request.form.get("dob"))
            if not dob_valid:
                flash(dob_message, "danger")

            is_valid, message = validate_user_input(None, password, new_email, dob)
            if not is_valid:
                flash(message, "danger")
                return redirect("/settings")
            user.email = new_email
            try:
                db.session.commit()
                flash("Your e-mail has been changed succesfully", "success")
            except Exception as e:
                logging.error(f"Error during commit: {e}")
                flash("There was an error updating your email.", "danger")
                return redirect("/playlists")
        elif action == "delete_account":
            email = request.form.get("email")
            password = request.form.get("password")
            dob = datetime.strptime(request.form.get("dob"), "%Y-%m-%d").date()
            dob_valid, dob_message = is_valid_date(request.form.get("dob"))
            if not dob_valid:
                flash(dob_message, "danger")
                return redirect("/settings")

            if (
                user.email != email
                or not check_password_hash(user.password, password)
                or dob != user.date_of_birth
            ):
                flash("Provided information is incorrect.", "danger")
                return redirect("/settings")

            db.session.delete(user)
            db.session.commit()
            session.clear()
            flash("Your account and all associated data have been deleted.", "success")
            return redirect(url_for("index"))
        elif action == "unlink":
            user.token = None
            user.refresh_token = None
            user.expiration_time = None
            user.spotify_name = "No account connected"
            db.session.commit()
            flash("Your Spotify account has been unlinked.", "success")

        return redirect(url_for("settings"))
    return render_template("settings.html", spotify_display_name=spotify_display_name)


# Login routes
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    username = request.form.get("username")
    password = request.form.get("password")
    user = User.query.filter_by(username=username).first()
    if user is None or not check_password_hash(user.password, password):
        flash("Invalid username or password", "danger")
        return redirect("/login")
    session["user_id"] = user.id
    flash("You are now logged in", "success")
    return redirect("/")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    session.clear()
    if request.method == "GET":
        return render_template("forgot.html")
    username = request.form.get("username")
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash("Username does not exist.")
        return redirect("/forgot")
    email = request.form.get("email")
    if email != user.email:
        flash("User with this e-mail does not exist.")
        return redirect("/forgot")
    newpassword = request.form.get("newpassword")
    confirm_password = request.form.get("confirm_password")
    if newpassword != confirm_password:
        flash("Passwords do not match.")
        return redirect("/forgot")
    if len(newpassword) < 8:
        flash("New password must be at least 8 characters long.")
        return redirect("/forgot")
    user.password = generate_password_hash(newpassword)
    db.session.commit()
    flash("Your new password set successfully.")
    return redirect("/login")


# Register routes
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")
        date_of_birth_str = request.form.get("dob")
        if not date_of_birth_str:
            flash("Date of Birth is required.", "danger")
            return redirect("/register")
        dob = datetime.strptime(date_of_birth_str, "%Y-%m-%d").date()

        dob_valid, dob_message = is_valid_date(request.form.get("dob"))
        if not dob_valid:
            flash(dob_message, "danger")
            return redirect("/register")

        is_valid, message = validate_user_input(username, password, email, dob)
        if not is_valid:
            flash(message, "danger")
            return redirect("/register")

        newuser = User(
            username=request.form.get("username"),
            password=generate_password_hash(request.form.get("password")),
            date_of_birth=datetime.strptime(request.form.get("dob"), "%Y-%m-%d").date(),
            email=request.form.get("email"),
        )

        try:
            db.session.add(newuser)
            db.session.commit()
            flash("Registered successfully", "success")
        except Exception as e:
            db.session.rollback()
            flash("Could not save user.", "danger")
            return redirect("/register")

        session["user_id"] = newuser.id
        return redirect("/")
    else:
        return render_template("register.html")


def reset_db():
    with current_app.app_context():
        db.drop_all()
        db.create_all()


# Debug routes
@app.route("/reset_db")
def reset_database():
    reset_db()
    flash("Database has been reset.", "success")
    return redirect(url_for("login"))


@app.before_request
def require_login():
    allowed_routes = ["login", "register", "static", "forgot", "home"]
    if request.endpoint not in allowed_routes:
        user_id = session.get("user_id")
        if user_id is None:
            flash("You must be logged in to view this page.", "danger")
            return redirect(url_for("login"))


@app.route("/debug/credentials", methods=["GET"])
def debug_credentials():
    client_id_value = os.environ.get("SPOTIFY_CLIENT_ID")
    client_secret_value = os.environ.get("SPOTIFY_CLIENT_SECRET")

    return f"Client ID: {client_id_value}, Client Secret: {client_secret_value}"


@app.route("/debug/token", methods=["GET"])
def debug_token():
    try:
        token = get_token()
        return f"Token: {token}"
    except Exception as e:
        return f"Error occurred: {str(e)}"


if __name__ == "__main__":
    app.run(debug=True)
