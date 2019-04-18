# !/usr/bin/env python3
from model import Base, User, Category, Item
from flask import Flask, jsonify, request, url_for
from flask import abort, g, render_template, redirect
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker, scoped_session
from sqlalchemy import create_engine, desc
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
from flask import make_response
from flask import session as login_session
import requests
import json
from flask_httpauth import HTTPBasicAuth

import logging
logging.basicConfig()
auth = HTTPBasicAuth()
CLIENT_ID = json.loads(
    open('client_secret.json', 'r').read())['web']['client_id']
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
Session = scoped_session(DBSession)
app = Flask(__name__)

app.secret_key = 'jwUy2YpROhIizqzKyIJDTrdT'

@app.route('/')
def latestItems():
    session = Session()
    items = session.query(Item).order_by(desc(Item.id)).limit(8)
    categories = session.query(Category).all()
    if 'username' not in login_session or login_session['username'] is None:
        return render_template('publicLatestItem.html', categories=categories,
                               items=items, header="Latest")
    else:
        return render_template('latestItem.html', categories=categories,
                               items=items, header="Latest")



@app.route('/catalog/<category>/items')
def selectedCategory(category):
    session = Session()
    categories = session.query(Category).all()
    selectedCatagory = session.query(Category).filter_by(name=category).one()
    items = session.query(Item).filter_by(
                category_id=selectedCatagory.id).all()
    if 'username' not in login_session or login_session['username'] is None:
        return render_template('publicLatestItem.html', categories=categories,
                               items=items, header=category)
    else:
        return render_template('latestItem.html', categories=categories,
                               items=items, header=category)


@app.route('/catalog/<category>/<item>')
def selectedItem(category, item):
    session = Session()
    itemName = item.replace('%20', ' ')
    selectedCategory = session.query(Category).filter_by(name=category).one()
    selectedItem = session.query(Item).filter_by(name=itemName).one()
    if 'username' not in login_session or login_session['username'] is None:
        user = False
    elif selectedItem.user.username == login_session['username']:
        user = True
    else:
        user = False
    return render_template('itemDescription.html', header=itemName,
                           description=selectedItem.description, user=user)


@app.route('/catalog/addItem', methods=['GET', 'POST'])
def addItem():
    session = Session()
    if 'username' not in login_session or login_session['username'] is None:
        return redirect(url_for('latestItems'))
    elif request.method == 'POST':
        formName = request.form['name']
        existingItem = session.query(Item).filter_by(name=formName).count()
        if existingItem > 0:
            return redirect(url_for('latestItems'))
        else:
            formDescription = request.form['description']
            formCategoryName = request.form['category']
            formCategory = session.query(Category).filter_by(
                name=formCategoryName).one()
            formUsername = login_session['username']
            formUser = session.query(User).filter_by(
                username=formUsername).one()
            item = Item(name=formName, description=formDescription,
                        category=formCategory, user=formUser)
            session.add(item)
            session.commit()
            return redirect(url_for('selectedCategory',
                                    category=formCategoryName))
    else:
        categories = session.query(Category).all()
        return render_template('addItem.html', categories=categories)


@app.route('/catalog/<item>/edit', methods=['GET', 'POST'])
def editItem(item):
    session = Session()
    selectedItem = session.query(Item).filter_by(name=item).one()
    if 'username' not in login_session or login_session['username'] is None:
        return redirect(url_for('latestItems'))
    elif login_session['username'] != selectedItem.user.username:
        return redirect(url_for('latestItems'))
    else:
        categories = session.query(Category).all()
        if request.method == 'POST':
            selectedItem.name = request.form['name']
            selectedItem.description = request.form['description']
            selectedItem.category = session.query(Category).filter_by(
                name=request.form['category']).one()
            session.add(selectedItem)
            session.commit()
            return redirect(url_for('selectedItem',
                            category=selectedItem.category.name,
                            item=selectedItem.name))
        else:
            print 'item selected in edit: ' + str(selectedItem.name)
            return render_template('editItem.html', item=selectedItem,
                                   categories=categories)


@app.route('/catalog/<item>/delete', methods=['POST', 'GET'])
def deleteItem(item):
    session = Session()
    selectedItem = session.query(Item).filter_by(name=item).one()
    if 'username' not in login_session or login_session['username'] is None:
        return redirect(url_for('latestItems'))
    elif login_session['username'] != selectedItem.user.username:
        return redirect(url_for('latestItems'))
    else:
        if request.method == 'POST':
            session.delete(selectedItem)
            session.commit()
            return redirect(url_for('latestItems'))
        else:
            return render_template('deleteItem.html', item=selectedItem)


@app.route('/catalog.json', methods=['GET'])
def getJSON():
    session = Session()
    categories = session.query(Category).all()
    x = {}

    x['Category'] = [i.serialize for i in categories]

    for j in x['Category']:
        items = session.query(Item).filter_by(category_id=int(j['id']))
        j['Item'] = [t.serialize for t in items]

    return jsonify(x)


@app.route('/token')
@auth.login_required
def get_auth_token():
    session = Session()
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})


# adding Oauth:
@app.route('/oauth/<provider>', methods=['POST'])
def login(provider):
    session = Session()
    if provider == 'google':
        # Step1 parse the auth code
        auth_code = request.data
        print 'inside login method' + str(auth_code)
        # Step2 exhange for token
        try:
            # Upgrade the auth code into a credentials object
            oauth_flow = flow_from_clientsecrets('client_secret.json',
                                                 scope='')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(auth_code)
        except FlowExchangeError:
            response = make_response(json.dumps(
                'Failed to upgrade the authorizate code.'), 401)
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
            response = make_response(json.dumps(
                                     "Token's user ID doesn't match given" +
                                     "user ID."), 401)
            response.headers['Content-Type'] = 'application/json'
            return response
        # Verify that the access token is valid for this app.
        if result['issued_to'] != CLIENT_ID:
            response = make_response(json.dumps("Token's client ID does " +
                                                " not match app's."), 401)
            response.headers['Content-Type'] = 'application/json'
            return response
        # Check if user is already logged in
        stored_credentials = login_session.get('credentials')
        stored_gplus_id = login_session.get('gplus_id')
        if stored_credentials is not None and gplus_id == stored_gplus_id:
            response = make_response(json.dumps('Current user is already ' +
                                                'connected.'), 200)
            response.headers['Content-Type'] = 'application/json'
            return response
        print "Step 2 Complete! Access Token : %s " % credentials.access_token
        # STEP 3 - Find User or make a new one
        # Get user info
        h = httplib2.Http()
        userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
        params = {'access_token': credentials.access_token, 'alt': 'json'}
        answer = requests.get(userinfo_url, params=params)
        data = answer.json()
        name = data['name']
        picture = data['picture']
        email = data['email']
        # See if user exists, if it doesn't make a new one
        user = session.query(User).filter_by(email=email).first()
        print "user: " + str(user.username)
        if not user:
            user = User(username=name, picture=picture, email=email)
            session.add(user)
            session.commit()
        g.user = user
        login_session['username'] = name
        login_session['picture'] = picture
        login_session['email'] = email
        # STEP 4 - Make token
        token = user.generate_auth_token(600)
        login_session['token'] = token
        login_session['access_token'] = credentials.access_token
        # STEP 5 - Send back token to the client
        # return jsonify({'token': token.decode('ascii')})

        return redirect(url_for('latestItems'))
        # return jsonify({'token': token.decode('ascii'), 'duration': 600})
    else:
        return 'Unrecoginized Provider'


@app.route('/logout', methods=['POST'])
def logout():
    session = Session()
    print 'INSIDE LOGOUT'
    access_token = login_session['access_token']
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user not connected.'),
                                 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print 'In gdisconnect access token is %s',  access_token
    u = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % (access_token)
    h = httplib2.Http()
    result = h.request(u, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        print 'setting login_session to None'
        login_session['username'] = None
        session.close()
        return redirect(url_for('latestItems'))
    else:
        response = make_response(json.dumps('Failed to revoke token for' +
                                            'given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return redirect(url_for('latestItems'))


@auth.verify_password
def verify_password(username_or_token, password):
    session = Session()
    user_id = User.verify_auth_token(username_or_token)
    if user_id:
        user = session.query(User).filter_by(id=user_id).one()
    else:
        user = session.query(User).filter_by(
            username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


if __name__ == '__main__':
    app.secret_key = 'jwUy2YpROhIizqzKyIJDTrdT'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
