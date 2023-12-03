from flask import Flask
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///pcs.db'
db = SQLAlchemy(app)

with app.app_context():
    from DB_SERVER.models import *
    db.create_all()