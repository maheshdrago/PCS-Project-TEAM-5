from DB_SERVER import db
from sqlalchemy.orm import backref
from DB_SERVER import bcrypt



class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False)
    keys = db.relationship('Keys', backref="user", cascade="all,delete", uselist=False)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)
    
class Directories(db.Model):
    id = id = db.Column(db.Integer, primary_key=True)
    directory_name = db.Column(db.String(300), unique=True)
    mappings = db.relationship('ChunkFileMappings', backref="directories", cascade="all,delete", lazy=True)

class ChunkFileMappings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(300), unique=True)
    mappings = db.relationship('ChunkMappings', backref="chunkfilemappings", cascade="all,delete", lazy=True)
    directory_id = db.Column(db.Integer, db.ForeignKey("directories.id"), nullable=True)

class ChunkMappings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chunk_number = db.Column(db.Integer, nullable=False)
    chunk_peer = db.Column(db.String(100))
    chunk_id = db.Column(db.String(300))
    fileMapping_id = db.Column(db.Integer, db.ForeignKey("chunk_file_mappings.id"))

class Permissions(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(300))
    permissions = db.Column(db.String(100))
    username = db.Column(db.String(100))

class DirPermissions(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dir_name = db.Column(db.String(300))
    permissions = db.Column(db.String(100))
    username = db.Column(db.String(100))

class Keys(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_key = db.Column(db.String(1000))
    private_key = db.Column(db.String(1000))
    fernet_key = db.Column(db.String(1000))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))