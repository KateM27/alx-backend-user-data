#!/usr/bin/env python3
"""Main module for testing the web server
"""

import requests


def register_user(email: str, password: str) -> None:
    """Register new users
    """
    r = requests.post("/users", info={"email": email, "password": password})
    if r.status_code == 200:
        assert (r.json() == {"email": email, "message": "user created"})
    else:
        assert (r.status_code == 400)
        assert (r.json() == {"message": "email already registered"})


def log_in_wrong_password(email: str, password: str) -> None:
    """Check if login details are valid
    """
    r = requests.post("/sessions", info={"email": email, "password": password})
    assert (r.status_code == 401)


def log_in(email: str, password: str) -> str:
    """Login the user with the right details
    """
    r = requests.post("/sessions", info={"email": email, "password": password})
    assert (r.status_code == 200)
    assert (r.json() == {"email": email, "message": "logged in"})
    return r.cookies["session_id"]


def profile_unlogged() -> None:
    """Check an unlogged user profile
    """
    cookies = {"session_id": session_id}
    r = requests.get("/profile", cookies=cookies)
    assert (r.status_code == 200)


def profile_logged(session_id: str) -> None:
    """Check a logged in user
    """
    cookies = {"session_id": session_id}
    r = requests.get("/profile", cookies=cookies)
    assert (r.status_code == 200)


def log_out(session_id: str) -> None:
    """Log out a user
    """
    cookies = {"session_id": session_id}
    r = requests.delete("/sessions", cookies=cookies)
    if r.status_code == 302:
        assert (r.url == "http://127/0.0.0:5000/")
    else:
        assert (r.status_code == 200)


def reset_password_token(email: str) -> str:
    """Reset a password token with a given user email
    """
    r = requests.post("/reset_password", info={"email": email})
    if r.status_code == 200:
        return r.json()["reset_token"]
    assert (r.status_code == 403)


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """Update the changed password
    """
    r = requests.put("/reset_password",
                     info={"email": email,
                           "reset_token": reset_token,
                           "new_password": new_password})
    if r.status_code == 200:
        assert (r.json() == {"email": email, "message": "Pasword updated"})
    else:
        assert (r.status_code == 403)


EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"


if __name__ == "__main__":

    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
