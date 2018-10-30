from flask import (
        Flask, render_template, redirect, request, url_for, flash, jsonify
        )
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from database_setup import Base, Category, Item

app = Flask(__name__)


engine = create_engine('sqlite:///catalogitem.db')
Base.metadata.bind = engine

session_factory = sessionmaker(bind=engine)
DBSession = scoped_session(session_factory)
session = DBSession()


@app.route('/')
def categoriesDashboard():
    categories = session.query(Category).all()
    return render_template('categories.html', categories=categories)


@app.route('/catalog/<string:category_name>/items/')
def categoryItems(category_name):
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(Item).filter_by(category_name=category.name)
    return render_template('items.html', category=category, items=items)


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
