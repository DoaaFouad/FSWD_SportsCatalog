from flask import Flask, render_template, request, redirect
from flask import jsonify, url_for, flash

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_config import Base, Category, Item, User

from flask import session as login_session
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
import requests
from flask import make_response

from utils import Utils

import random
import string
import collections

# from dict2xml import dict2xml
from xml.etree.ElementTree import Element, SubElement, Comment, tostring

app = Flask(__name__)

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "SportsCatalog"

session = Utils.connect()


# start of Auth
# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('User connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    # OAuth2Credentials object is not JSON serializable error -
    # add the .to_json()
    login_session['credentials'] = credentials.to_json()
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION -
    # for later use when fb is also added to login
    login_session['provider'] = 'google'

    # see if user exists, if it does'nt make new one
    user_id = getUserID(data['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    print(user_id)
    print(login_session['username'])
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;"' 
    '"border-radius: 150px;-webkit-border-radius: 150px;"'
    '"-moz-border-radius: 150px;">'
    flash("you are now logged in as %s" % login_session['username'])
    print("done!")
    return output


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['credentials']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# Helper Functions

def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['credentials']
            del login_session['username']
            del login_session['email']
            del login_session['picture']
            del login_session['user_id']
            del login_session['provider']
            flash("You have successfully been logged out.")
        return redirect(url_for('showHome'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showHome'))

# End of Auth
###################################
# CRUD


# show all sports categories
@app.route('/')
@app.route('/catalog')
def showHome():
    categories = session.query(Category).order_by(asc(Category.name))
    items = session.query(Item).all()
    if 'username' not in login_session:
        return render_template('publicCatalog.html',
                               categories=categories,
                               items=items)
    else:
        return render_template('catalog.html',
                               categories=categories,
                               items=items)


@app.route('/catalog/<string:category_name>/')
@app.route('/catalog/<string:category_name>/item/')
def showItem(category_name):
    category = session.query(Category).filter_by(name=category_name).one()
    creator = getUserInfo(category.user_id)
    items = session.query(Item).filter_by(category_id=category.id).all()
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('publicItem.html',
                                items=items,
                                category=category,
                                creator=creator)
    else:
        return render_template('item.html',
                                items=items,
                                category=category,
                                creator=creator)


# create new category
@app.route('/category/new/', methods=['GET', 'POST'])
def newCategory():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newCategory = Category(name=request.form['name'],
                               image=request.form['image'],
                               user_id=login_session['user_id'])
        session.add(newCategory)
        flash('New Category %s Successfully Created' % newCategory.name)
        session.commit()
        return redirect(url_for('showHome'))
    else:
        return render_template('newCategory.html')


# edit category
@app.route('/category/<string:category_name>/edit/', methods=['GET', 'POST'])
def editCategory(category_name):
    editedCategory = session.query(
        Category).filter_by(name=category_name).one()
    if 'username' not in login_session:
        return redirect('/login')
        print 'username'
    if editedCategory.user_id != login_session['user_id']:
        return "<script>function myFunction()"
        " {alert('You are not authorized');}"
        "</script><body onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['name']:
            editedCategory.name = request.form['name']
            flash('Category Successfully Edited %s' % editedCategory.name)
            return redirect(url_for('showHome'))
    else:
        return render_template('editCategory.html', category=editedCategory)


# delete category
@app.route('/category/<string:category_name>/delete/', methods=['GET', 'POST'])
def deleteCategory(category_name):
    categoryToDelete = session.query(Category).filter_by(name=category_name).one()
    if 'username' not in login_session:
        return redirect('/login')
    print(categoryToDelete.user_id)
    print(login_session['user_id'])
    if categoryToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction()"
        " {alert('You are not authorized');}"
        "</script><body onload='myFunction()''>"

    if request.method == 'POST':
       session.delete(categoryToDelete)
       flash('%s Successfully Deleted' % categoryToDelete.name)
       session.commit()
       return redirect(url_for('showHome'))
    else:
        return render_template('deleteCategory.html',
                               category=categoryToDelete)

# Making an API Endpoint (GET Request)
# JSON APIs to view category info
@app.route('/catalogbyitems/JSON')
def catalogItemsJSON():
    categories = session.query(Category).all()
    serializedCategoryItems = []
    for c in categories:
        serializedCategory = c.serialize
        items = session.query(Item).filter_by(category_id=c.id).all()
        serializedItems = []
        for i in items:
            serializedItems.append(i.serialize)
        serializedCategory['items'] = serializedItems
        serializedCategoryItems.append(serializedCategory)
    return jsonify(Category=serializedCategoryItems)

# list all categroies
@app.route('/category/JSON')
def categoriesJSON():
    categories = session.query(Category).all()
    return jsonify(categories=[r.serialize for r in categories])

# list all items of the category
@app.route('/allitems/JSON')
def allItemsJSON():
    items = session.query(Item).all()
    return jsonify(items=[i.serialize for i in items])

# filter by name
@app.route('/catalog/<string:category_name>/JSON')
def itemByCategoryJSON(category_name):
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(CategoryItem).filter_by(category_id=category.id).all()
    return jsonify(Category=[category.serialize],
                   Items=[item.serialize for item in items])
# End of JSON
####################################
# for items
@app.route('/category/<string:category_name>/item/new/',
           methods=['GET', 'POST'])
def newCategoryItem(category_name):
    if 'username' not in login_session:
        return redirect('/login')
    category = session.query(Category).filter_by(name=category_name).one()
    if login_session['user_id'] != category.user_id:
        return "<script>function myFunction()"
        " {alert('You are not authorized');}"
        "</script><body onload='myFunction()''>"
    if request.method == 'POST':
        newItem = Item(name=request.form['name'],
                       description=request.form['description'],
                       category_id=category.id,
                       user_id=category.user_id)
        session.add(newItem)
        session.commit()
        flash('New Item %s  Successfully Created' % (newItem.name))
        return redirect(url_for('showItem', category_name=category_name))
    else:
        return render_template('newCategoryItem.html',
                               category_name=category_name)

# edit item
@app.route('/category/<string:category_name>/<string:item_name>/edit',
           methods=['GET', 'POST'])
def editCategoryItem(category_name, item_name):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(Item).filter_by(name=item_name).one()
    category = session.query(Category).filter_by(name=category_name).one()
    if login_session['user_id'] != category.user_id:
        return "<script>function myFunction()"
        " {alert('You are not authorized');}"
        "</script><body onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        session.add(editedItem)
        session.commit()
        flash('Category Item Successfully Edited')
        return redirect(url_for('showItem', category_name=category_name))
    else:
        return render_template('editCategoryItem.html',
                               category_name=category_name,
                               item_name=item_name,
                               item=editedItem)

# delete item
@app.route('/category/<string:category_name>/<string:item_name>/delete',
           methods=['GET', 'POST'])
def deleteCategoryItem(category_name, item_name):
    if 'username' not in login_session:
        return redirect('/login')
    category = session.query(Category).filter_by(name=category_name).one()
    itemToDelete = session.query(Item).filter_by(name=item_name).one()
    if login_session['user_id'] != category.user_id:
        return "<script>function myFunction()"
        " {alert('You are not authorized');}"
        "</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Category Item Successfully Deleted')
        return redirect(url_for('showItem', category_name=category_name))
    else:
        return render_template('deleteCategoryItem.html', item=itemToDelete)

# End of CRUD
###################################
# app entry point

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8080)
