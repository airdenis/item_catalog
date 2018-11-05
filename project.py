from flask import (
        Flask, render_template, redirect, request, url_for, flash, jsonify
        )
from sqlalchemy import create_engine, func, desc
from sqlalchemy.orm import sessionmaker, joinedload
from sqlalchemy.orm import scoped_session
from database_setup import Base, Category, Item
from flask import session as login_session
import random
import string

app = Flask(__name__)


engine = create_engine('sqlite:///catalogitem.db')
Base.metadata.bind = engine

session_factory = sessionmaker(bind=engine)
DBSession = scoped_session(session_factory)
session = DBSession()


@app.route('/catalog.json/')
def catalogJSON():
    categories = session.query(Category).options(
            joinedload(Category.items)
            ).all()
    session.close()
    return jsonify(dict(Category=[
        dict(c.serialize, items=[
            i.serialize for i in c.items
            ]) for c in categories
        ]))


@app.route('/login/')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    print state
    login_session['state'] = state
    return "The current session state is {}".format(login_session['state'])


@app.route('/')
def categoriesDashboard():
    categories = session.query(Category).all()
    count = session.query(Category).count()
    items = session.query(Item).order_by(desc('init_time')).limit(count).all()
    return render_template(
            'categories.html',
            categories=categories,
            items=items
            )


@app.route('/catalog/<string:category_name>/items/')
def categoryItems(category_name):
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(Item).filter_by(
            cat_id=category.id
            ).order_by(desc('init_time'))
    count = session.query(Item).filter_by(
            cat_id=category.id
            ).count()
    return render_template(
            'items.html',
            category=category,
            items=items,
            count=count
            )


@app.route('/catalog/<string:category_name>/<string:item_title>/')
def itemDescription(category_name, item_title):
    category = session.query(Category).filter_by(name=category_name).one()
    item = session.query(Item).filter_by(
            title=item_title,
            cat_id=category.id
            ).one()
    return render_template(
            'itemdescription.html',
            category=category,
            item=item
            )


@app.route('/catalog/new/', methods=['GET', 'POST'])
def newItem():
    categories = session.query(Category).all()
    if request.method == 'POST':
        if request.form['category'] and request.form['title']:
            category = session.query(Category).filter_by(
                    name=request.form['category']
                    ).one()
            new_item = Item(
                    title=request.form['title'],
                    description=request.form['description'],
                    cat_id=category.id,
                    init_time=func.now()
                    )
            session.add(new_item)
            session.commit()
            return redirect(url_for('categoriesDashboard'))
        else:
            return render_template('newitem.html', categories=categories)
    else:
        return render_template('newitem.html', categories=categories)


@app.route('/catalog/<string:item_title>/edit', methods=['GET', 'POST'])
def editItem(item_title):
    edit_item = session.query(Item).filter_by(title=item_title).one()
    category_selected = session.query(Category).filter_by(
            id=edit_item.cat_id
            ).one()
    categories = session.query(Category).all()
    if request.method == 'POST':
        if request.form['category'] and request.form['title']:
            category_selected = session.query(Category).filter_by(
                    name=request.form['category']
                    ).one()
            if request.form['title']:
                edit_item.title = request.form['title']
            if request.form['description']:
                edit_item.description = request.form['description']
            edit_item.cat_id = category_selected.id
            edit_item.init_time = func.now()
            session.add(edit_item)
            session.commit()
            session.close()
            return redirect(url_for('categoriesDashboard'))
        else:
            return render_template(
                    'edititem.html',
                    item=edit_item,
                    category_selected=category_selected,
                    categories=categories
                    )
    else:
        return render_template(
                'edititem.html',
                item=edit_item,
                category_selected=category_selected,
                categories=categories
                )


@app.route(
        '/catalog/<string:item_title>/delete/',
        methods=['GET', 'POST']
        )
def deleteItem(item_title):
    delete_item = session.query(Item).filter_by(title=item_title).one()
    if request.method == 'POST':
        session.delete(delete_item)
        session.commit()
        session.close()
        return redirect(url_for('categoriesDashboard'))
    else:
        return render_template('deleteitem.html', item=delete_item)


if __name__ == '__main__':
    app.secret_key = 'super secret key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
