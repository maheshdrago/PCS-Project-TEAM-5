from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///pcs.db'
db = SQLAlchemy(app)

with app.app_context():
    from DB_SERVER.models import *
    db.create_all()