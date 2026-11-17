import getpass
import hmac
import io
import os
import secrets
import time
import webbrowser
from threading import Thread, Timer

import numpy as np
from cryptography.fernet import InvalidToken
from flask import Flask, abort, redirect, render_template_string, request, send_file
from jinja2 import BaseLoader

from openrecall import vault
from openrecall.config import appdata_folder, screenshots_path
from openrecall.database import (
    create_db,
    delete_entries_between,
    get_all_entries,
    get_timestamps,
)
from openrecall.nlp import cosine_similarity, get_embedding
from openrecall.screenshot import load_image, record_screenshots_thread
from openrecall.utils import human_readable_time, timestamp_to_human_readable

app = Flask(__name__)

PORT = 8082
# Only these names may appear in the Host header: a malicious website that
# points its own domain at 127.0.0.1 (DNS rebinding) still sends its own name
ALLOWED_HOSTNAMES = {"127.0.0.1", "localhost"}
SESSION_COOKIE = "openrecall_session"
BROWSER_OPEN_DELAY_SECONDS = 1.0
SESSION_IDLE_SECONDS = 5 * 60
IDLE_CHECK_SECONDS = 30
MAX_FAILED_LOGINS = 5
LOGIN_BLOCK_SECONDS = 30

# One session at a time: OpenRecall has a single user, and logging in again
# from another browser ends the previous session
_session = {"id": None, "last_activity": 0.0}
_login_attempts = {"failed": 0, "blocked_until": 0.0}

app.jinja_env.filters["human_readable_time"] = human_readable_time
app.jinja_env.filters["timestamp_to_human_readable"] = timestamp_to_human_readable
app.jinja_env.globals["idle_ms"] = SESSION_IDLE_SECONDS * 1000

base_template = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OpenRecall</title>
  <!-- Bootstrap CSS -->
  <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.3.0/font/bootstrap-icons.css">
  <style>
    .slider-container {
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 20px;
    }
    .slider {
      width: 80%;
    }
    .slider-value {
      margin-top: 10px;
      font-size: 1.2em;
    }
    .image-container {
      margin-top: 20px;
      text-align: center;
    }
    .image-container img {
      max-width: 100%;
      height: auto;
    }
  </style>
</head>
<body>
{% block nav %}
<nav class="navbar navbar-light bg-light">
  <div class="container">
    <form class="form-inline my-2 my-lg-0 flex-grow-1 d-flex" action="/search" method="get">
      <input class="form-control flex-grow-1 mr-sm-2" type="search" name="q" placeholder="Search" aria-label="Search">
      <button class="btn btn-outline-secondary my-2 my-sm-0" type="submit">
        <i class="bi bi-search"></i>
      </button>
    </form>
    <form class="form-inline my-2 my-lg-0 ml-sm-2" action="/forget" method="post"
          onsubmit="return confirm('Permanently delete everything captured in this period?');">
      <select class="form-control mr-2" name="minutes" aria-label="Period to forget">
        <option value="15">Last 15 minutes</option>
        <option value="60">Last hour</option>
        <option value="1440">Last 24 hours</option>
      </select>
      <button class="btn btn-outline-danger" type="submit">Forget</button>
    </form>
    <form id="lockForm" class="form-inline my-2 my-lg-0 ml-sm-2" action="/lock" method="post">
      <button class="btn btn-outline-dark" type="submit"><i class="bi bi-lock"></i> Lock</button>
    </form>
  </div>
</nav>
<script>
  // The server cannot take back a page that is already on screen, so the
  // page locks itself when nobody uses it
  let idleTimer;
  function resetIdleTimer() {
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => document.getElementById('lockForm').submit(), {{ idle_ms }});
  }
  ['mousemove', 'keydown', 'scroll', 'click'].forEach(
    (eventName) => document.addEventListener(eventName, resetIdleTimer)
  );
  resetIdleTimer();
</script>
{% endblock %}
{% block content %}

{% endblock %}

  <!-- Bootstrap and jQuery JS -->
  <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.3/dist/umd/popper.min.js"></script>
  <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
  
</body>
</html>
"""


class StringLoader(BaseLoader):
    def get_source(self, environment, template):
        if template == "base_template":
            return base_template, None, lambda: True
        return None, None, None


app.jinja_env.loader = StringLoader()


login_template = """
{% extends "base_template" %}
{% block nav %}{% endblock %}
{% block content %}
<div class="container" style="max-width: 400px; margin-top: 15vh;">
  <h4 class="mb-3"><i class="bi bi-lock"></i> OpenRecall is locked</h4>
  {% if error %}<div class="alert alert-danger">{{ error }}</div>{% endif %}
  <form action="/login" method="post">
    <input class="form-control mb-2" type="password" name="password"
           placeholder="Password" aria-label="Password" autofocus required>
    <button class="btn btn-primary btn-block" type="submit">Unlock</button>
  </form>
</div>
{% endblock %}
"""


def _end_session() -> None:
    """Logs out and forgets the private key, so the history is unreadable again."""
    _session["id"] = None
    vault.lock()


def _lock_if_idle() -> None:
    idle_seconds = time.time() - _session["last_activity"]
    if _session["id"] is not None and idle_seconds > SESSION_IDLE_SECONDS:
        _end_session()


def _has_valid_session() -> bool:
    _lock_if_idle()
    if _session["id"] is None:
        return False
    cookie = request.cookies.get(SESSION_COOKIE, "")
    # Constant-time comparison so the session id cannot be guessed by timing
    if not hmac.compare_digest(cookie.encode("utf-8"), _session["id"].encode("utf-8")):
        return False
    _session["last_activity"] = time.time()
    return True


@app.before_request
def require_authentication():
    """Only someone who knows the password may use the web UI.

    Without this anyone at the computer, any local program, other user
    account or website could view screenshots or POST to /forget.
    """
    hostname = request.host.rsplit(":", 1)[0]
    if hostname not in ALLOWED_HOSTNAMES:
        abort(403)

    if request.endpoint == "login" or _has_valid_session():
        return None
    if request.method == "GET":
        return redirect("/login")
    abort(403)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template_string(login_template, error=None)

    if time.time() < _login_attempts["blocked_until"]:
        error = f"Too many wrong passwords. Wait {LOGIN_BLOCK_SECONDS} seconds."
        return render_template_string(login_template, error=error), 429

    if not vault.unlock(request.form.get("password", "")):
        _login_attempts["failed"] += 1
        if _login_attempts["failed"] >= MAX_FAILED_LOGINS:
            _login_attempts["failed"] = 0
            _login_attempts["blocked_until"] = time.time() + LOGIN_BLOCK_SECONDS
        return render_template_string(login_template, error="Wrong password."), 401

    _login_attempts["failed"] = 0
    _session["id"] = secrets.token_urlsafe(32)
    _session["last_activity"] = time.time()
    response = redirect("/")
    # SameSite=Strict: other websites cannot send requests with this cookie
    response.set_cookie(
        SESSION_COOKIE, _session["id"], httponly=True, samesite="Strict"
    )
    return response


@app.route("/lock", methods=["POST"])
def lock():
    _end_session()
    response = redirect("/login")
    response.delete_cookie(SESSION_COOKIE)
    return response


@app.route("/")
def timeline():
    # connect to db
    timestamps = get_timestamps()
    return render_template_string(
        """
{% extends "base_template" %}
{% block content %}
{% if timestamps|length > 0 %}
  <div class="container">
    <div class="slider-container">
      <input type="range" class="slider custom-range" id="discreteSlider" min="0" max="{{timestamps|length - 1}}" step="1" value="{{timestamps|length - 1}}">
      <div class="slider-value" id="sliderValue">{{timestamps[0] | timestamp_to_human_readable }}</div>
    </div>
    <div class="image-container">
      <img id="timestampImage" src="/static/{{timestamps[0]}}.webp" alt="Image for timestamp">
    </div>
  </div>
  <script>
    const timestamps = {{ timestamps|tojson }};
    const slider = document.getElementById('discreteSlider');
    const sliderValue = document.getElementById('sliderValue');
    const timestampImage = document.getElementById('timestampImage');

    slider.addEventListener('input', function() {
      const reversedIndex = timestamps.length - 1 - slider.value;
      const timestamp = timestamps[reversedIndex];
      sliderValue.textContent = new Date(timestamp * 1000).toLocaleString();  // Convert to human-readable format
      timestampImage.src = `/static/${timestamp}.webp`;
    });

    // Initialize the slider with a default value
    slider.value = timestamps.length - 1;
    sliderValue.textContent = new Date(timestamps[0] * 1000).toLocaleString();  // Convert to human-readable format
    timestampImage.src = `/static/${timestamps[0]}.webp`;
  </script>
{% else %}
  <div class="container">
      <div class="alert alert-info" role="alert">
          Nothing recorded yet, wait a few seconds.
      </div>
  </div>
{% endif %}
{% endblock %}
""",
        timestamps=timestamps,
    )


@app.route("/search")
def search():
    q = request.args.get("q", "").strip()
    if not q:
        return render_template_string(
            '{% extends "base_template" %}{% block content %}<div class="container"><div class="alert alert-warning">Voer een zoekopdracht in.</div></div>{% endblock %}'
        )

    entries = get_all_entries()
    if not entries:
        return render_template_string(
            '{% extends "base_template" %}{% block content %}<div class="container"><div class="alert alert-info">Geen resultaten gevonden.</div></div>{% endblock %}'
        )

    embeddings = [entry.embedding for entry in entries]
    query_embedding = get_embedding(q)
    similarities = [cosine_similarity(query_embedding, emb) for emb in embeddings]
    indices = np.argsort(similarities)[::-1]
    sorted_entries = [entries[i] for i in indices]

    return render_template_string(
        """
{% extends "base_template" %}
{% block content %}
    <div class="container">
        <div class="row">
            {% for entry in entries %}
                <div class="col-md-3 mb-4">
                    <div class="card">
                        <a href="#" data-toggle="modal" data-target="#modal-{{ loop.index0 }}">
                            <img src="/static/{{ entry.timestamp }}.webp" alt="Image" class="card-img-top">
                        </a>
                    </div>
                </div>
                <div class="modal fade" id="modal-{{ loop.index0 }}" tabindex="-1" role="dialog" aria-hidden="true">
                    <div class="modal-dialog modal-xl" role="document" style="max-width: none; width: 100vw; height: 100vh; padding: 20px;">
                        <div class="modal-content" style="height: calc(100vh - 40px); width: calc(100vw - 40px); padding: 0;">
                            <div class="modal-body" style="padding: 0;">
                                <img src="/static/{{ entry.timestamp }}.webp" alt="Image" style="width: 100%; height: 100%; object-fit: contain; margin: 0 auto;">
                            </div>
                        </div>
                    </div>
                </div>
            {% endfor %}
        </div>
    </div>
{% endblock %}
""",
        entries=sorted_entries,
    )


@app.route("/forget", methods=["POST"])
def forget():
    """
    Permanently deletes everything captured in the last few minutes.
    Give the user a way to control data, usefull for example if a password
    appeared on screen, or other sensitive data, that the user accidentally recorded

    """
    minutes = request.form.get("minutes", type=int)
    if minutes is None or minutes < 1:
        return "Invalid number of minutes", 400
    now = int(time.time())
    delete_entries_between(now - minutes * 60, now)
    return redirect("/")


@app.route("/static/<filename>")
def serve_image(filename):
    filepath = os.path.join(screenshots_path, filename)
    if not os.path.exists(filepath):
        return "Not found", 404

    try:
        image = load_image(filepath)
    except InvalidToken:
        # Recorded with keys that no longer exist (auth.json was deleted)
        return "Not found", 404
    buffer = io.BytesIO()
    image.save(buffer, format="WEBP")
    buffer.seek(0)
    return send_file(buffer, mimetype="image/webp")


def _choose_password() -> None:
    """Asks for the password on first start; without it nothing can be viewed."""
    print("Choose the password that protects your OpenRecall history.")
    print("Without it nobody, not even you, can view the recordings.")
    while True:
        password = getpass.getpass("Password: ")
        if len(password) < vault.MIN_PASSWORD_LENGTH:
            print(f"Use at least {vault.MIN_PASSWORD_LENGTH} characters.")
            continue
        if getpass.getpass("Repeat password: ") != password:
            print("The passwords do not match.")
            continue
        break
    vault.set_up(password)


def _lock_when_idle_thread() -> None:
    """Locks an idle session even when no request arrives to notice it."""
    while True:
        time.sleep(IDLE_CHECK_SECONDS)
        _lock_if_idle()


if __name__ == "__main__":
    # Before recording starts: recording needs the public key
    if not vault.is_set_up():
        _choose_password()

    create_db()
    t = Thread(target=record_screenshots_thread)
    t.start()
    Thread(target=_lock_when_idle_thread, daemon=True).start()

    access_url = f"http://127.0.0.1:{PORT}/"
    print(f"Open OpenRecall at: {access_url}")
    # Delayed so the server is listening by the time the browser connects
    Timer(BROWSER_OPEN_DELAY_SECONDS, webbrowser.open, args=[access_url]).start()
    app.run(host="127.0.0.1", port=PORT)
