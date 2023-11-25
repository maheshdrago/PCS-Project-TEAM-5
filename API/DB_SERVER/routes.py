from DB_SERVER import app, db
from DB_SERVER.models import Users
from flask import request 


@app.route("/register", methods=['POST'])
def register():
    data = request.json
    username = data['username']
    password = data['password']

    user = Users(username=username, password=password)
    db.session.add(user)
    db.session.commit()

    return "User with Username : {} Registerd Successfully".format(username)

@app.route("/login", methods=["GET"])
def login():
    username = request.args.get('username')
    password = request.args.get("password")

    user = Users.query.filter_by(username=username).first()

    if user and user.password==password:
        return "Success"
    else:
        return "Fail"