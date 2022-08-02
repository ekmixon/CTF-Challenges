
from gevent import monkey; monkey.patch_all()

import bottle
import json
import jwt
from bottle_redis import RedisPlugin
from uuid import uuid4
from random import randint

app = bottle.Bottle()
FLAG = "flag{Y-ARHq29rhchpFJjyJyr}"

@app.get('/api/users/<username>')
def callback(username, rdb):
    "Returns if an username exists"
    user = rdb.get(f"user:{username}")

    if user is None:
        bottle.abort(404, "The user does not exist")
    user = json.loads(user)

    auth_header = bottle.request.headers.get('Authorization')
    auth = False
    if auth_header is not None and auth_header.startswith("Bearer "):
        jwt_header = auth_header.split(" ")[1]
        try:
            user_jwt = jwt.decode(jwt_header, user.get('token'), algorithms=['HS256'])
            if user_jwt.get('username') == username and \
               user_jwt.get('timestamp', 0) > user.get('last_timestamp', 0):

                user['last_timestamp'] = max(user.get('timestamp', 0), user_jwt.get('timestamp', 0))
                rdb.set(f"user:{user.get('username')}", json.dumps(user))

                auth = True
            print(repr(user_jwt))
        except jwt.exceptions.DecodeError as err:
            print(repr(err))

    if not auth or user is None:
        return {
            'exists': user is not None
        }
    if user.get('show_flag', False):
        user['locked'] = False
        rdb.set(f"user:{user.get('username')}", json.dumps(user))

    return {
        "name": user.get('name'),
        "username": user.get('username'),
        "token": user.get('token')
    }

@app.get('/api/usert/<token>')
def callback(token, rdb):
    "Returns the username that belongs to the token"
    username = rdb.get(f"token:{token}")
    if username is None:
        bottle.abort(404, "The user does not exist.")
    return {
        'username': username.decode('utf-8')
    }

@app.post('/api/users')
def callback(rdb):
    "Creates a new user"

    data = bottle.request.json

    fields = ["name", "username", "password"]
    if missing_fields := [
        field
        for field in fields
        if field not in data or len(data.get(field)) <= 0
    ]:
        return {
            "success": False,
            "message": f"All fields are required. Missing fields: {', '.join(missing_fields)}",
        }


    user = rdb.get(f"user:{data.get('username')}")
    if user is not None:
        return {"success": False, "message": "This username already exists."}

    token_generated = False
    while not token_generated:
        token = uuid4().hex
        rtoken = rdb.get(f"token:{token}")
        if rtoken is None:
            token_generated = True

    rdb.set(
        f"user:{data.get('username')}",
        json.dumps(
            {
                "name": data.get("name"),
                "username": data.get("username"),
                "password": data.get("password"),
                "token": token,
                "metric_count": 0,
                "locked": False,
                "show_flag": False,
                "last_timestamp": 0,
            }
        ),
    )

    rdb.set(f"token:{token}", data.get("username"))

    return {"success": True}


@app.post('/api/authenticate')
def callback(rdb):
    "Logins a user"

    data = bottle.request.json
    if 'username' not in data or 'password' not in data:
        return {"success": False, "message": "Username and Password required"}

    user = rdb.get(f"user:{data.get('username')}")

    success = False
    if user is not None:
        user = json.loads(user)
        if user.get('password') == data.get('password'):
            success = True

    if success:
        return {
            "success": True, "data": {
                "name": user.get('name'),
                "username": user.get('username'),
                "token": user.get('token')
            }
        }
    else:
        return {"success": False, "message": "Invalid username or password"}

@app.get('/api/metrics')
def callback(rdb):

    auth_header = bottle.request.headers.get('Authorization')

    if auth_header is None or not auth_header.startswith("Bearer "):
        bottle.abort(403, "Forbidden")

    jwt_header = auth_header.split(" ")[1]
    try:
        unvalidated_jwt = jwt.decode(jwt_header, verify=False)
        if unvalidated_jwt is None or 'username' not in unvalidated_jwt:
            bottle.abort(403, "Forbidden")

        user = rdb.get(f"user:{unvalidated_jwt.get('username')}")
        if user is None:
            bottle.abort(403, "Forbidden")

        user = json.loads(user)
        user_jwt = jwt.decode(jwt_header, user.get('token'), algorithms=['HS256'])

        if user.get('last_timestamp', 0) >= user_jwt.get('timestamp', 0):
            bottle.abort(403, "Forbidden")

        user['last_timestamp'] = max(user.get('timestamp', 0), user_jwt.get('timestamp', 0))
        user['metric_count']   = user.get('metric_count', 0) + 1
        if user['metric_count'] >= 3 and not user.get('show_flag', False):
            user['locked'] = True
            user['show_flag'] = True
            user['password'] = "9X%DuAHDj!!PjhQK%p^gPjSgG9"

        rdb.set(f"user:{user.get('username')}", json.dumps(user))

        print(repr(user_jwt))
        print(repr(user))
    except jwt.exceptions.DecodeError as e:
        bottle.abort(403, "Forbidden")

    if user.get('locked', False):
        return {"success": False, "message": "Detected an unknown access location. For your security we changed your password and logged you out."}

    metrics = {
        'metrics': [
            {'name': 'Current Users', 'value': randint(52, 57)},
            {'name': 'Max Users', 'value': 133},
            {'name': 'Current Ping', 'value': randint(52, 2333)},
            {'name': 'Max Ping', 'value': 80082}
        ]
    }

    if user.get('show_flag', False):
        metrics['metrics'].append({'name': 'Flag', 'value': 'flag{Y-ARHq29rhchpFJjyJyr}'})

    return metrics

@app.get('/')
def callback():
    response = bottle.static_file("index.html", "./static")
    response.set_header("Cache-Control", "public, max-age=1")
    return response

@app.get('/<path:path>')
def callback(path):
    response =  bottle.static_file(path, "./static")
    response.set_header("Cache-Control", "public, max-age=1")
    return response


if __name__ == '__main__':
    app.install(RedisPlugin(host="localhost"))
    app.run(
        host='localhost',
        port=8080,
        debug=True,
        reloader=True
    )
else:
    app.install(RedisPlugin(host="redis"))
    application = app


