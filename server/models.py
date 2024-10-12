from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)  # Ensure username is unique and not null
    _password_hash = db.Column(db.String, nullable=False)  # Password hash must not be null

    @hybrid_property
    def password_hash(self):
        """Prevent access to the password hash."""
        raise Exception('Password hashes may not be viewed.')

    @password_hash.setter
    def password_hash(self, password):
        """Set the password hash when a password is assigned."""
        password_hash = bcrypt.generate_password_hash(password)
        self._password_hash = password_hash

    def authenticate(self, password):
        """Check if the provided password matches the stored password hash."""
        return bcrypt.check_password_hash(self._password_hash, password)

    def to_dict(self):
        """Convert user object to dictionary, excluding password hash."""
        return {
            'id': self.id,
            'username': self.username
        }

    def __repr__(self):
        return f'User {self.username}, ID: {self.id}'
