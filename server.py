'''Authentication demo application'''

import hmac
import hashlib
import base64
import json

from typing import Optional
from fastapi import FastAPI, Cookie, Body
from fastapi.responses import Response


app = FastAPI()

SECRET_KEY = "4dfa7aacc330962110a4df679b0ce6c797236c6da74728b4ee893647c4d59c03"
PASSWORD_SALT = "53f27e3330b2abb2691a7e1a136500e88aef2a9d12540d9e2faccdb4365255bf"

def sign_data(data : str) -> str:
    '''Return signed data via sha256'''
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()

def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    '''Return username from sighned string'''    
    username_base64, sign = username_signed.split(".")
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username

def verify_password(username: str, password: str) -> bool:
    '''Verify password method. Return boolean.'''
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password = users[username]["password"]
    return  password_hash == stored_password

users = {
    "nikita@user.com" : {
        "name": "Никита",
        "password": "c25af18b7c7b6664715343cb589a0911b1503123a518b96dc73cc95987eef6d0",
        "balance": 100_000
    },
    "dima@user.com" : {
        "name": "Дима",
        "password": "867c07ba4858ac0a87f1011807ed77f7c043d293c79b98aec3ae07ef7ad4e196",
        "balance": 555_555
    }
}



@app.get("/")
def index_page(username : Optional[str] = Cookie(default=None)):
    '''Main route. Auth and userpage.'''
    with open("templates/login.html", 'r', encoding="utf8", errors="surrogateescape") as file:
        login_page = file.read()
    if not username:
        return Response(login_page, media_type="text/html")
    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    try:
        user = users[valid_username]
    except KeyboardInterrupt:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    return Response(
        f"Привет, {users[valid_username]['name']}!Вы уже авторизировались до этого!"
        f"<br/> Баланс: {user['balance']}", media_type="text/html")



@app.post("/login")
def process_login_page(data: dict = Body(...)):
    '''Login. Post method, sending username and password from form.'''
    username = data["username"]
    password = data["password"]
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(
            json.dumps({
                "success": False,
                "message": "Я вас не знаю!"
            }),
            media_type="application/json")

    response = Response(
        json.dumps({
            "success": True,
            "message": f"Ваш логин: {username}, пароль: {password}<br/> Баланс: {user['balance']}"
        }),
        media_type="application/json")

    username_signed = base64.b64encode(username.encode()).decode() + "." + \
        sign_data(username)
    response.set_cookie(key="username", value=username_signed)
    return response
    