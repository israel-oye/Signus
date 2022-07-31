from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String())
    authenticated = db.Column(db.Boolean, default=False)

    # def __init__(self, name, email) -> None:
    #     self.name = name
    #     self.email = email
        
        

    def __repr__(self) -> str:
        return super().__repr__()

    @property
    def is_active(self):
        return True

    
    def get_id(self):
        return self.id

    @property
    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
     
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)