from sqlalchemy import Column, ForeignKey, Integer, String, DateTime, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))


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
