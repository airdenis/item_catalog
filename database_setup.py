from sqlalchemy import Column, ForeignKey, Integer, String, DateTime, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context
import random
import string
from itsdangerous import \
    (
        TimedJSONWebSignatureSerializer as
        Serializer, BadSignature, SignatureExpired
    )

Base = declarative_base()


def secret_key_generator():
    return ''.join(
            random.choice(
                string.ascii_uppercase + string.digits
                ) for x in xrange(32)
            )


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    password_hash = Column(String(64))
    image = Column(String(250))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(secret_key_generator(), expires_in=expiration)
        return s.dumps({'id': 'self.id'})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(secret_key_generator())
        try:
            data = s.loads(token)
        except SignatureExpired:
            # Valid Token, but expired
            return None
        except BadSignature:
            # Invalid Token
            return None
        user_id = data['id']
        return user_id


class Category(Base):
    __tablename__ = 'category'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)

    @property
    def serialize(self):
        return{
                'id': self.id,
                'name': self.name,
                }


class Item(Base):
    __tablename__ = 'item'

    title = Column(String(80), nullable=False)
    id = Column(Integer, primary_key=True)
    description = Column(String(1000))
    image = Column(String(250))
    init_time = Column(DateTime, default=func.now())
    cat_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category, backref='items')
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        return{
                'cat_id': self.cat_id,
                'description': self.description,
                'id': self.id,
                'title': self.title,
                'init_time': self.init_time,
                }


engine = create_engine('sqlite:///catalogitem.db')


Base.metadata.create_all(engine)
