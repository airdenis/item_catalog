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
    items = session.query(Item).filter_by(
            category_name=category.name
            ).order_by('time desc')
    return render_template('items.html', category=category, items=items)


@app.route('/catalog/<string:category_name>/<string:item_name>/')
def itemDescription(category_name, item_name):
    category = session.query(Category).filter_by(name=category_name).one()
    item = session.query(Item).filter_by(
            name=item_name,
            category_name=category.name
            ).one()
    return render_template(
            'itemdescription.html',
            category=category,
            item=item
            )


@app.route('/catalog/new/', methods=['GET', 'POST'])
def newItem():
    if request.method == 'POST':
        new_item = Item(
                name=request.form['name'],
                description=request.form['description'],
                category_name=request.form['category']
                )
        session.add(new_item)
        session.commit()
        session.close()
        return redirect(url_for('categoriesDashboard'))
    else:
        return render_template('newitem.html')


@app.route(
        '/catalog/<string:category_name>/<string:item_name>/delete/',
        methods=['GET', 'POST']
        )
def deleteItem(category_name, item_name):
    category = session.query(Category).filter_by(name=category_name).one()
    delete_item = session.query(Item).filter_by(
            name=item_name,
            category_name=category.name
            ).one()
    print category.name
    if request.method == 'POST':
        session.delete(delete_item)
        session.commit()
        session.close()
        return redirect(url_for('categoryItems', category_name=category_name))
    else:
        return render_template(
                'deleteitem.html',
                category=category,
                item=delete_item
                )


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
