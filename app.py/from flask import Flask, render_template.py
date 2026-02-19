from pydoc import pager
import random
from flask import Flask, render_template, request, redirect, url_for, session, send_file
import sqlite3
import hashlib
import os
import time
from encryption_utils import hide_text_in_image, reveal_text_from_image

app = Flask(__name__, template_folder="../templates", static_folder="../static")

app.secret_key = "your_secret_key"  # Change this in production!

admin_users = {}


# Ensure the encrypted_images folder exists
images_dir = os.path.join(app.root_path, "encrypted_images")
if not os.path.exists(images_dir):
    os.makedirs(images_dir)


import re
import base64
from PIL import Image
import io

import os
from flask import url_for, render_template, request


def is_valid_base64(s):
    try:
        # Clean up whitespace/newlines
        s = s.strip().replace("\n", "").replace("\r", "")
        # Validate characters
        if not re.fullmatch(r"[A-Za-z0-9+/=]+", s):
            return False
        # Try decoding
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False


def can_open_as_image(b64text):
    try:
        img_bytes = base64.b64decode(b64text)
        img = Image.open(io.BytesIO(img_bytes))
        img.verify()  # verifies it's a valid image file
        return True
    except Exception:
        return False


# Initialize database and create users table if not exists
def init_db():
    """Initializes the database and creates the users table if it doesn't exist."""
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    # Updated table with new columns
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            age INTEGER NOT NULL,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """
    )
    conn.commit()
    conn.close()


# Database setup and helper code omitted (use your existing init_db etc.)


def generate_captcha():
    # Simple math captcha
    num1 = random.randint(1, 9)
    num2 = random.randint(1, 9)
    session["captcha_answer"] = str(num1 + num2)
    return f"{num1} + {num2} = ?"


#  LOGIN ROUTE
@app.route("/", methods=["GET", "POST"])
def login():
    """Handles the user login page."""
    # If user is already fully authenticated, send them to the dashboard.
    if session.get("username") and session.get("captcha_passed"):
        return redirect(url_for("user_dashboard"))

    # If user is logged in but hasn't passed captcha, send them to the auth page.
    if session.get("username"):
        return redirect(url_for("admin_auth_page"))

    # Standard login logic for users who are not logged in.
    msg = ""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            msg = "Please enter both username and password."
            return render_template("login.html", msg=msg)

        password_hash = hashlib.sha256(password.encode()).hexdigest()

        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username, password_hash),
        )
        user = c.fetchone()
        conn.close()

        if user:
            session["username"] = user[1]
            # On successful login, always go to the CAPTCHA page first.
            return redirect(url_for("admin_auth_page"))
        else:
            msg = "Incorrect username or password."

    return render_template("login.html", msg=msg)


#  CAPTCHA AUTHENTICATION ROUTE
@app.route("/auth", methods=["GET", "POST"])
def admin_auth_page():
    """Handles the CAPTCHA security check after login."""
    # If a non-logged-in user tries to access this page, send them away.
    if "username" not in session:
        return redirect(url_for("login"))

    # If user has already passed the captcha, don't ask again. Send to dashboard.
    if session.get("captcha_passed"):
        return redirect(url_for("user_dashboard"))

    if request.method == "POST":
        answer = request.form.get("captcha_answer", "")
        if answer == session.get("captcha_answer"):
            session["captcha_passed"] = True
            return redirect(url_for("user_dashboard"))
        else:
            error = "Incorrect answer. Please try again."
            session["captcha_question"] = generate_captcha()
            return render_template(
                "admin_auth.html",
                captcha_question=session["captcha_question"],
                error=error,
            )

    # For a GET request, generate a new question.
    session["captcha_question"] = generate_captcha()
    session["captcha_passed"] = False  # Ensure this is reset
    return render_template(
        "admin_auth.html", captcha_question=session["captcha_question"]
    )


# USER DASHBOARD ROUTE (Encryption/Decryption Tools)
@app.route("/user")
def user_dashboard():
    """The main user page, accessible only after full authentication."""
    # CRITICAL FIX: This logic correctly redirects to the right step (login or captcha)
    if not session.get("username") or not session.get("captcha_passed"):
        return redirect(url_for("login"))

    username = session.get("username")
    return render_template("user.html", username=username)


# REGISTRATION ROUTE
# In app.py


@app.route("/register", methods=["GET", "POST"])
def register():
    """Handles new user registration with expanded fields."""
    msg = ""
    if request.method == "POST":
        # Get all the new form fields
        name = request.form.get("name")
        age = request.form.get("age")
        email = request.form.get("email")
        username = request.form.get("username")
        password = request.form.get("password")

        # Simple validation to ensure all fields are filled
        if not all([name, age, email, username, password]):
            msg = "Please fill out all fields."
            return render_template("register.html", msg=msg)

        password_hash = hashlib.sha256(password.encode()).hexdigest()

        try:
            conn = sqlite3.connect("users.db")
            c = conn.cursor()
            # Updated INSERT statement with all the new columns
            c.execute(
                "INSERT INTO users (name, age, email, username, password) VALUES (?, ?, ?, ?, ?)",
                (name, age, email, username, password_hash),
            )
            conn.commit()
            conn.close()
            # On success, redirect to the login page
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            # This error happens if the username or email is already taken
            msg = "That username or email already exists. Please choose another."

    return render_template("register.html", msg=msg)


# LOGOUT ROUTE
@app.route("/logout")
def logout():
    """Clears the session to log the user out."""
    session.clear()
    return redirect(url_for("login"))


@app.route("/home")
def home():
    return redirect(url_for("user_dashboard"))


# encrypt text to image

from text_image_stego_utils import (
    hide_encrypted_text_in_image,
    extract_and_decrypt_text_from_image,
)
import uuid, os
from flask import render_template, request, url_for


@app.route("/encrypt_text_image", methods=["GET", "POST"])
def encrypt_text_image():
    result = None
    download_link = None
    if request.method == "POST":
        file = request.files.get("imagefile")
        text = request.form.get("text")
        password = request.form.get("password")
        if not file or not text or not password:
            result = "Please choose an image, enter a message and password."
        else:
            orig_filename = f"cover_{uuid.uuid4().hex}.png"
            orig_path = os.path.join(app.root_path, "encrypted_images", orig_filename)
            file.save(orig_path)
            output_filename = f"stego_{uuid.uuid4().hex}.png"
            output_path = os.path.join(
                app.root_path, "encrypted_images", output_filename
            )
            try:
                hide_encrypted_text_in_image(orig_path, text, password, output_path)
                result = "Encryption successful!"
                download_link = url_for(
                    "download_encrypted_image", filename=output_filename
                )
            except Exception as e:
                result = f"Encryption error: {e}"
    return render_template(
        "encrypt_text_image.html", result=result, download_link=download_link
    )


# decrypt text to image


@app.route("/decrypt_text_image", methods=["GET", "POST"])
def decrypt_text_image():
    result = None
    if request.method == "POST":
        file = request.files.get("imagefile")
        password = request.form.get("password")
        if not file or not password:
            result = "Please upload the stego image and enter the password."
        else:
            import uuid

            test_filename = f"stego_input_{uuid.uuid4().hex}.png"
            test_path = os.path.join(app.root_path, "encrypted_images", test_filename)
            file.save(test_path)
            try:
                recovered_text = extract_and_decrypt_text_from_image(
                    test_path, password
                )
                result = recovered_text
            except Exception as e:
                result = (
                    "Decryption failed (wrong password, no message, or corrupt image)."
                )
    return render_template("decrypt_text_image.html", result=result)


# download images


@app.route("/download_encrypted_image/<filename>")
def download_encrypted_image(filename):
    if "username" not in session:
        return redirect(url_for("login"))
    # Optional: check file ownership here
    filepath = os.path.join(app.root_path, "encrypted_images", filename)
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    else:
        return "File not found", 404


# encrypt image to text


from image_text_crypto_utils import encrypt_image_to_text, decrypt_text_to_image
import os, uuid
from flask import Flask, render_template, request, url_for


@app.route("/encrypt_image_text", methods=["GET", "POST"])
def encrypt_image_text():
    result = None
    encrypted_text = None
    download_link = None

    if request.method == "POST":
        file = request.files.get("imagefile")
        password = request.form.get("password")

        if not file or not password:
            result = "Please choose an image and enter a password."
        else:
            import uuid, os
            from image_text_crypto_utils import encrypt_image_to_text

            # Save the uploaded image temporarily in static/outputs/
            static_outputs = os.path.join(app.root_path, "../static", "outputs")
            os.makedirs(static_outputs, exist_ok=True)
            image_name = f"img_{uuid.uuid4().hex}.png"
            image_path = os.path.join(static_outputs, image_name)
            file.save(image_path)

            try:
                # Encrypt and get text
                encrypted_text = encrypt_image_to_text(image_path, password)

                # Save text as .txt in static/outputs
                text_filename = f"encrypted_{uuid.uuid4().hex}.txt"
                text_path = os.path.join(static_outputs, text_filename)
                print("Saving file to:", text_path)
                with open(text_path, "w") as tf:
                    tf.write(encrypted_text)

                # Now, provide the download link for the new file
                download_link = url_for("static", filename=f"outputs/{text_filename}")
                result = "Encryption successful! Download your encrypted text below."
            except Exception as e:
                result = f"Encryption error: {e}"
            finally:
                # Remove temp image regardless of outcome
                if os.path.exists(image_path):
                    os.remove(image_path)

    return render_template(
        "encrypt_image_text.html",
        result=result,
        encrypted_text=encrypted_text,
        download_link=download_link,
    )


@app.route("/decrypt_image_text", methods=["GET", "POST"])
def decrypt_image_text():
    result = None
    image_url = None

    if request.method == "POST":
        file = request.files.get("textfile")
        password = request.form.get("password")
        encrypted_text = request.form.get("encrypted_text", "").strip()
        text_content = None

        if file and file.filename:
            text_content = file.read().decode("utf-8")
        elif encrypted_text:
            text_content = encrypted_text
        else:
            result = "Please provide encrypted text (paste or file) and password."

        if text_content and password:
            import uuid, os, base64
            from image_text_crypto_utils import decrypt_text_to_image

            static_outputs = os.path.join(app.root_path, "static", "outputs")
            os.makedirs(static_outputs, exist_ok=True)
            restored_name = f"restored_{uuid.uuid4().hex}.png"
            restored_path = os.path.join(static_outputs, restored_name)

            try:
                decrypt_text_to_image(text_content, password, restored_path)
                with open(restored_path, "rb") as imgfile:
                    b64img = base64.b64encode(imgfile.read()).decode("utf-8")
                    image_url = f"data:image/png;base64,{b64img}"
                result = "Decryption successful! Your image is below."
            except Exception:
                result = "Decryption failed: Incorrect password or invalid input."
            finally:
                if os.path.exists(restored_path):
                    os.remove(restored_path)

    return render_template(
        "decrypt_image_text.html", result=result, image_url=image_url
    )


# encryption for audio
import os
import uuid
from flask import render_template, request, url_for
from audio_crypto_utils import encrypt_audio_with_password, decrypt_audio_with_password


@app.route("/encrypt_audio", methods=["GET", "POST"])
def encrypt_audio():
    result = None
    download_link = None
    if request.method == "POST":
        file = request.files.get("audiofile")
        password = request.form.get("password")

        if not file or not password:
            result = "Please upload a WAV file and enter a password."
        elif not file.filename.lower().endswith(".wav"):
            result = "Only WAV files are supported."
        else:
            orig_filename = f"audio_{uuid.uuid4().hex}.wav"
            orig_path = os.path.join(app.root_path, "encrypted_images", orig_filename)
            file.save(orig_path)

            encrypted_filename = f"audio_encrypted_{uuid.uuid4().hex}.audenc"
            encrypted_path = os.path.join(
                app.root_path, "encrypted_images", encrypted_filename
            )

            try:
                encrypt_audio_with_password(orig_path, password, encrypted_path)
                result = "Audio encrypted successfully!"
                download_link = url_for(
                    "download_encrypted_image", filename=encrypted_filename
                )
                os.remove(orig_path)  # clean temp file
            except Exception as e:
                result = f"Encryption error: {str(e)}"

    return render_template(
        "encrypt_audio.html", result=result, download_link=download_link
    )


@app.route("/decrypt_audio", methods=["GET", "POST"])
def decrypt_audio():
    result = None
    wav_download = None
    if request.method == "POST":
        file = request.files.get("audiofile")
        password = request.form.get("password")

        if not file or not password:
            result = "Please upload your encrypted file and enter password."
        elif not file.filename.lower().endswith(".audenc"):
            result = "Only .audenc files are supported."
        else:
            uploaded_filename = f"decrypt_{uuid.uuid4().hex}.audenc"
            uploaded_path = os.path.join(
                app.root_path, "encrypted_images", uploaded_filename
            )
            file.save(uploaded_path)

            restored_wav_name = uploaded_filename.replace(".audenc", "_restored.wav")
            restored_wav_path = os.path.join(
                app.root_path, "encrypted_images", restored_wav_name
            )

            try:
                decrypt_audio_with_password(uploaded_path, password, restored_wav_path)
                result = "Decryption successful! Download your audio below."
                wav_download = url_for(
                    "download_encrypted_image", filename=restored_wav_name
                )
                os.remove(uploaded_path)  # clean temp file
            except Exception:
                result = "Decryption failed: Incorrect password or corrupt file."
                if os.path.exists(restored_wav_path):
                    os.remove(restored_wav_path)
                if os.path.exists(uploaded_path):
                    os.remove(uploaded_path)

    return render_template(
        "decrypt_audio.html", result=result, wav_download=wav_download
    )


# encrypt video
import os
import uuid
from flask import render_template, request, url_for
from video_crypto_utils import encrypt_video_with_password, decrypt_video_with_password


@app.route("/encrypt_video", methods=["GET", "POST"])
def encrypt_video():
    result = None
    download_link = None
    if request.method == "POST":
        file = request.files.get("videofile")
        password = request.form.get("password")

        if not file or not password:
            result = "Please upload a video file and enter a password."
        elif not file.filename.lower().endswith(".mp4"):
            result = "Only MP4 video files are supported."
        else:
            orig_filename = f"video_{uuid.uuid4().hex}.mp4"
            orig_path = os.path.join(app.root_path, "encrypted_images", orig_filename)
            os.makedirs(os.path.dirname(orig_path), exist_ok=True)
            file.save(orig_path)

            encrypted_filename = f"video_encrypted_{uuid.uuid4().hex}.videnc"
            encrypted_path = os.path.join(
                app.root_path, "encrypted_images", encrypted_filename
            )

            try:
                encrypt_video_with_password(orig_path, password, encrypted_path)
                result = "Video encryption successful!"
                download_link = url_for(
                    "download_encrypted_image", filename=encrypted_filename
                )
                os.remove(orig_path)
            except Exception as e:
                result = f"Encryption error: {e}"

    return render_template(
        "encrypt_video.html", result=result, download_link=download_link
    )


# decrypt video


@app.route("/decrypt_video", methods=["GET", "POST"])
def decrypt_video():
    result = None
    video_download = None
    if request.method == "POST":
        file = request.files.get("videofile")
        password = request.form.get("password")

        if not file or not password:
            result = "Please upload your encrypted file and enter password."
        elif not file.filename.lower().endswith(".videnc"):
            result = "Only .videnc files are supported."
        else:
            uploaded_filename = f"decrypt_{uuid.uuid4().hex}.videnc"
            uploaded_path = os.path.join(
                app.root_path, "encrypted_images", uploaded_filename
            )
            file.save(uploaded_path)

            restored_video_name = uploaded_filename.replace(".videnc", "_restored.mp4")
            restored_video_path = os.path.join(
                app.root_path, "encrypted_images", restored_video_name
            )

            try:
                decrypt_video_with_password(
                    uploaded_path, password, restored_video_path
                )
                result = "Decryption successful! Download your video below."
                video_download = url_for(
                    "download_encrypted_image", filename=restored_video_name
                )
                os.remove(uploaded_path)
            except Exception:
                result = "Decryption failed: Incorrect password or corrupt file."
                if os.path.exists(restored_video_path):
                    os.remove(restored_video_path)
                if os.path.exists(uploaded_path):
                    os.remove(uploaded_path)

    return render_template(
        "decrypt_video.html", result=result, video_download=video_download
    )


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
