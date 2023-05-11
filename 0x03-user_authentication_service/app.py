#!/usr/bin/env python3
"""Basic Flask app"""

from flask import Flask, abort, jsonify, redirect, request
from auth import Auth

app = Flask(__name__)
AUTH = Auth()


@app.route("/", methods="GET")
def message() -> str:
    """return a json payload"""
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods="POST")
def users() -> str:
    """register a user"""
    email = request.form.get("email")
    password = request.form.get("password")
    try:
        AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"})
    except Exception:
        return jsonify({"message": "email already registered"}), 400


@app.route("/sessions", methods="POST")
def login() -> str:
    """Implement login"""
    email = request.form.get("email")
    password = request.form.get("password")
    login_info = AUTH.valid_login(email, password)

    if login_info:
        session_id = AUTH.create_session(email)
        response = jsonify({"email": f"{email}", "message": "logged in"})
        response.set_cookie("session_id", session_id)
        return response
    else:
        abort(401)


@app.route("/sessions", methods="DELETE")
def logout() -> str:
    """Implement logout"""
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)

    if user:
        AUTH.destroy_session(user.id)
        return redirect("/")
    else:
        abort(403)


@app.route("/profile", methods="GET")
def profile() -> str:
    """Find the user's profile info"""
    session_id = request.cookies.get('session_id')
    user = AUTH.get_user_from_session_id(session_id)

    if user:
        return jsonify({"email": user.email}), 200
    else:
        abort(403)


@app.route("/reset_password", methods="POST")
def get_reset_password_token() -> str:
    """get a password reset token"""
    email = request.form.get("email")

    if email:
        token = AUTH.get_reset_password_token(email)
        return jsonify({"email": f"{email}", "reset_token": f"{token}"})
    else:
        abort(403)


@app.route("/reset_password", methods="PUT")
def update_password() -> str:
    """update user password"""
    email = request.form.get("email")
    reset_token = request.form.get("reset_token")
    password = request.form.get("new_password")

    try:
        AUTH.update_password(reset_token, password)
        return jsonify({"email": f"{email}",
                        "message": "Password updated"}), 200
    except Exception:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
