from flask import Flask, render_template, request, redirect, url_for, session
from flaskext.mysql import MySQL
import re
import crypto as secrets
import config


app = Flask(__name__)


mysql = MySQL()


app.config['SECRET_KEY'] = config.secret_key

app.config['MYSQL_DATABASE_HOST']=config.host
app.config['MYSQL_DATABASE_USER']=config.user
app.config['MYSQL_DATABASE_PASSWORD']=config.passwd
app.config['MYSQL_DATABASE_DB']=config.db

app.config['DEBUG'] = True


mysql.init_app(app)




@app.route('/', methods=['GET', 'POST'])
def login():
   
    msg = ''
   
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
 
        username = request.form['username']
        password = request.form['password']
        conn = mysql.connect()
        cur = conn.cursor()
        cur.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        #cur.execute('SELECT * FROM accounts WHERE username = %s AND password = %s', (username, password))
        account = cur.fetchone()
		

        if account:
            password_from_db = account[2]
            if secrets.check_password(password, password_from_db.encode('utf-8')):
   
                session['loggedin'] = True
                session['id'] = account[0]
                session['username'] = account[1]
                session['token'] = account[2]      
    
                return redirect(url_for('home'))
            else:
                msg="Bad password!"
        else:
    
            msg = 'Incorrect username/password!'

    return render_template('index.html', msg=msg)
	
	
@app.route('/logout')
def logout():

    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    session.pop('token', None)

    return redirect(url_for('login'))
   
@app.route('/register', methods=['GET', 'POST'])
def register():
 
    msg = ''

    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
      
        username = request.form['username']
        password = request.form['password']
        hashed_ps = secrets.get_hashed_password(password)
        token = secrets.get_key(username, password)
        email = request.form['email']
	
        conn = mysql.connect()
        cur = conn.cursor()
        cur.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cur.fetchone()
  
        if account:
            msg = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers!'
        elif not username or not password or not email:
            msg = 'Please fill out the form!'
        else:

            cur.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s, %s)', (username, hashed_ps, email, token))
            conn.commit()
            msg = 'You have successfully registered!'

    elif request.method == 'POST':
      
        msg = 'Please fill out the form!'

    return render_template('register.html', msg=msg)
	
	
@app.route('/home')
def home():

    if 'loggedin' in session:
        conn = mysql.connect()
        cur = conn.cursor()
        cur.execute('SELECT * FROM notes WHERE id_user = %s', (session['id'],))
        notes = cur.fetchall()

    
        if notes:
            notes_temp_decoder = []
            notes_list = []
            x = 0
            i = len(notes)

            while range(x, i):

                key = notes[x][4]
                encrypted_txt = str(notes[x][3]).encode('utf-8')
                text = secrets.decrypt(key, encrypted_txt).decode()

                notes_temp_decoder = [notes[x][0], notes[x][1], notes[x][2], text]
                notes_list.append(notes_temp_decoder)
                x += 1

            

            msg = "You got " + str(len(notes)) + " notes." 


            return render_template('home.html', username=session['username'], msg=msg, notes=notes_list)

        else:
            msg = "You dont have any note!"
            return render_template('home.html', username=session['username'], msg=msg)

    
        
    return redirect(url_for('login'))

@app.route('/home/add', methods=['GET', 'POST'])
def add():

    if 'loggedin' in session:
        if request.method == 'POST' and 'note_title' in request.form and 'note_text' in request.form:
        
            note_title = request.form['note_title']
            note_text = request.form['note_text']

            key = secrets.generate_key_derivation(session['token'].encode('utf-8'))
           
            encrypted_txt = secrets.encrypt(key, note_text)

            user_id = session['id']
            
                
            conn = mysql.connect()
            cur = conn.cursor()
            cur.execute('INSERT INTO notes VALUES (NULL, %s, %s, %s, %s)', (user_id, note_title, encrypted_txt, key))
            conn.commit()
            msg = "Note added!"
        return render_template('home.html', username=session['username'], msg=msg)

    return redirect(url_for('login'))




@app.route('/home/delete/<string:id>', methods=['GET', 'POST'])
def delete(id):

    if 'loggedin' in session:
        if request.method == 'POST':

            conn = mysql.connect()
            cur = conn.cursor()
            cur.execute('DELETE FROM notes WHERE id = %s', (id))
            conn.commit()
            msg = "Note deleted!"
        return render_template('home.html', username=session['username'], msg=msg)

    return redirect(url_for('login'))




@app.route('/profile')
def profile():

    if 'loggedin' in session:

        conn = mysql.connect()
        cur = conn.cursor()
        cur.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cur.fetchone()
        
        return render_template('profile.html', account=account)

    return redirect(url_for('login'))




@app.route('/profile/change/<string:id>', methods=['GET', 'POST'])
def change_password(id):

    if 'loggedin' in session:
        if request.method == 'POST':
            
            user_id = id
            username = session['username']
            password = request.form['password_change']
            hashed_ps = secrets.get_hashed_password(password)
            token = secrets.get_key(username, password)
            conn = mysql.connect()
            cur = conn.cursor()
            cur.execute('UPDATE accounts SET password = %s, token = %s WHERE id= %s',(hashed_ps, token, user_id))
            conn.commit()
            msg = "Password changed"

        return render_template('home.html', username=session['username'], msg=msg)

    return redirect(url_for('login'))

app.run(host="127.0.0.1", port="5050")