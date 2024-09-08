
from flask import Flask, render_template, request, redirect, url_for, session
from dotenv import dotenv_values
from pymongo.mongo_client import MongoClient 
from pymongo.server_api import ServerApi 
from bson.objectid import ObjectId
import hashlib
import time
from flask_misaka import Misaka
import datetime

secrets = dotenv_values(".env")
app = Flask(__name__)
Misaka(app)

app.secret_key = secrets['FLASK_SECRET']

db_client = MongoClient(secrets['MONGO_URI'], server_api=ServerApi('1')) 
db = db_client[secrets['DB_NAME']]
try:
    db.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)
articles = db['articles']
users = db['users']

def password_hash(username, password):
    return hashlib.sha256(str.encode(username + password + secrets['PASSWORD_SECRET'])).hexdigest()

@app.route('/')
def home():
    username = session['username'] if 'username' in session else None
    return render_template('home.html', articles=articles.find({'status': 'approved'}).sort('time', -1), username=username)

def is_username_valid(username):
    ok = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_'
    return all(c in ok for c in username)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form['email']

        error = None

        if not is_username_valid(username):
            error = 'Username can only contain a-z, A-Z, 0-9, and _'
        
        if len(username) > 25:
            error = 'Username is too long'

        if users.find_one({'username': username}) != None:
            error = 'Username taken'

        if username == '': 
            error = 'Cannot use an empty username'

        if password == '':
            error = 'Cannot use an empty password'

        if password != confirm_password:
            error = 'Passwords do not match'

        if users.find_one({'email': email}) != None:
            error = 'Email taken'

        if error != None:
            return render_template('signup.html', error=error, username=username, password=password, email=email)
        
        users.insert_one({
            'username': username,
            'password': password_hash(username, password),
            'email': None if email == '' else email
        })

        session['username'] = username

        return redirect(url_for('home')) 

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        error = None
        user = users.find_one({'username': username})
        if user == None:
            error = 'Invalid username'
        else:
            hash = password_hash(username, password)
            if hash != user['password']:
                error = 'Invalid password'
        
        if error != None:
            return render_template('login.html', error=error, username=username, password=password)
        
        session['username'] = username

        return redirect(url_for('home'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home')) 

article_categories = [
    'Uncategorized',
    'News',
    'Opinion',
    'Promo',
    'Entertainment'
]

@app.route('/edit', methods=['GET', 'POST'])
def edit():
    if request.method == 'POST':
        title = request.form['title'].strip()
        content = request.form['content']
        category = request.form['category']
        thumbnail = request.form['thumbnail']

        error = None
        
        if category not in article_categories:
            error = 'Invalid category'  
        if title == '':
            error = 'Cannot have empty title'
        if content.strip() == '':
            error = 'Article cannot be empty' 
        if 'username' not in session or users.find_one({'username': session['username']}) == None:
            error = 'Please login before posting'
        
        if error != None:
            return render_template('edit.html', article_categories=article_categories, error=error, guidelines_url=secrets['GUIDELINES_URL'])

        username = session['username']

        id = articles.insert_one({
            'author': username,
            'title': title,
            'content': content.replace('<','&lt;'),
            'category': category,
            'time': time.time(),
            'thumbnail': thumbnail if thumbnail != None else None,
            'status': 'pending'
        }).inserted_id

        return redirect(url_for('article', id=id, confirm_submit=True)) 

    return render_template('edit.html', article_categories=article_categories, guidelines_url=secrets['GUIDELINES_URL'])

def format_time(time):
    return datetime.datetime.fromtimestamp(time, datetime.timezone(datetime.timedelta(hours=5))).strftime('%m/%d/%Y')

@app.route('/article/<id>')
def article(id):
    article = articles.find_one({'_id': ObjectId(id)}) 
    if article == None:
        print('go home')
        return redirect(url_for('home'))
    return render_template('article.html',
        id=id,
        title=article['title'],
        content=article['content'].replace('<', '&lt;'),
        author=article['author'],
        category=article['category'],
        date=format_time(article['time']),
        confirm_submit='confirm_submit' in request.args)

@app.route('/guidelines')
def guidelines():
    return render_template('guidelines.html')

@app.route('/check', methods=['GET', 'POST'])
def check():
    if session['username'] != 'admin':
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        id = session['currArticleId']
        status = request.form['status']
        if status == 'delete':
            articles.delete_one({'_id': ObjectId(id)})
        else:
            articles.update_one(
                {'_id': ObjectId(id)},
                {'$set': {'status': status}}
            )

    article = articles.find_one({'status': 'pending'})

    if article == None:
        return 'No articles to review. Woo hoo!'

    session['currArticleId'] = str(article['_id'])
    return render_template('check.html',
        title=article['title'],
        content=article['content'],
        author=article['author'],
        category=article['category'],
        date=format_time(article['time']),
        thumbnail=article['thumbnail'] if 'thumbnail' in article else None)