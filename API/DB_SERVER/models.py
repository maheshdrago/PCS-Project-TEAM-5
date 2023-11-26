from DB_SERVER import db
from sqlalchemy.orm import backref

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    password = db.Column(db.String(40), nullable=False)

class ChunkFileMappings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(300), unique=True)
    mappings = db.relationship('ChunkMappings', backref="chunkfilemappings", cascade="all,delete", lazy=True)

class ChunkMappings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chunk_number = db.Column(db.Integer, nullable=False)
    chunk_peer = db.Column(db.String(100))
    chunk_id = db.Column(db.String(300))
    fileMapping_id = db.Column(db.Integer, db.ForeignKey("chunk_file_mappings.id"))
