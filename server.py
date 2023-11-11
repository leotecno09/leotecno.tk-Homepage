# IMPORTAZIONE MODULI
from flask import Flask, render_template, flash, url_for, request, redirect
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
import psycopg2																	
from psycopg2 import Error
import os
import random
import flask_login
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

# FLASK THINGS
app = Flask(__name__)
Bootstrap(app)

#bcrypt = Bcrypt(app)

# FLASK CONFIGURATIONS
app.config['SECRET_KEY'] = 'dasiugdjfr7h5g5'

# LOGIN MANAGER
login_manager = flask_login.LoginManager()
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(id):
	try:
		cur.execute('SELECT * FROM accounts WHERE id = %s', (id,))
		result = cur.fetchone()

		username = result[0]
		email = result[1]

		user = User(id)
		user.username = username
		user.email = email
		return user
	
	except Error as e:
		return redirect(url_for('error'))

# DATABASE
conn = psycopg2.connect(host = "localhost", database = "ltk", user = os.environ['postgres'], password = os.environ['PASSWORD_PSQL']) # CONFIGURARE CON APPOSITO SERVER PSQL DA CONFIGURARE

cur = conn.cursor()

# FUNZIONI BELLE A CASO
def checkUserRole():
	userID = current_user.id
	cur.execute('SELECT * FROM accounts WHERE id = %s', (userID,))
	result = cur.fetchone()

	role = result[6]
	
	return role

# ROUTES
@app.route('/')
def root():
	#flash('Benvenuto sul nuovo leotecno.tk!')
	return render_template('index.html')

@app.route('/account/register', methods=['GET', 'POST'])
def register():
	if request.method == 'POST':
		# DAL FORM
		username = request.form['name']
		email = request.form['email']
		password = request.form['password']
		passwordConfirm = request.form['passwordConfirm']
		checkbox = request.form.get('checkbox')
		print(checkbox)

		# CREATE LATO SERVER
		now = datetime.now()
		formatted_datetime = now.strftime("%d/%m/%Y %H:%M:%S")

		creation_date = formatted_datetime

		userID = ''.join([str(random.randint(0, 9)) for _ in range(9)])

		try:
			cur.execute('SELECT * FROM accounts WHERE email = %s', (email,))
			result = cur.fetchone()

			if result:
				flash('Un account con questa e-mail esiste già.', category='error')
				return redirect(url_for('register'))

			elif password != passwordConfirm:
				flash('Le due password non corrispondono!', category='error')
				return redirect(url_for('register'))

			elif len(password) < 7:
				flash('La password deve contenere almeno 7 caratteri.', category='error')
				return redirect(url_for('register'))	

			elif checkbox is None:
				flash('Per favore, accetta i termini di servizio.', category='error')
				return redirect(url_for('register'))

			else:									
				hashed_password = generate_password_hash(password, method='scrypt')

				try:
					cur.execute('INSERT INTO accounts (username, email, password, id, created_on)' 'VALUES (%s, %s, %s, %s, %s)', (format(username), format(email), format(hashed_password), int(userID), format(creation_date)))
					conn.commit()

					return '[POST] OK'

				except Error as e:
					return redirect(url_for('error'))
				
		except Error as e:
			return redirect(url_for('error'))			
	
	else:
		return render_template('register.html')

@app.route('/account/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		username = request.form['name']
		password = request.form['password']

		try:
			cur.execute('SELECT * FROM accounts WHERE username = %s OR email = %s', (format(username), format(username)))
			result = cur.fetchone()

			if result:
				# PROCEDI CON LOGIN (check password ecc...)
				stored_password = result[2]
				user_id = result[3]
				usernameFromDB = result[0]
				email = result[1]
				print (format(stored_password), format(password))
				
				if check_password_hash(stored_password, password):
					user = User(id=user_id)
					user.username = usernameFromDB
					user.email = email
					login_user(user, remember=True)
					return redirect(url_for('root'))
				
				else:
					flash("Password non corretta", category="error")
					return redirect(url_for('login'))


			else:
				flash("Impossibile trovare l'utente inserito", category="error")
				return redirect(url_for('login'))

		except Error as e:
			return redirect(url_for('error'))
	else:	
		return render_template('login.html')
	
@app.route('/account/logout')
@login_required
def logout():
	logout_user()
	flash('Logout effettuato con successo.')
	return redirect(url_for('login'))

@app.route('/account/settings')
@login_required
def accountSetings():
	return render_template('account-settings.html')

@app.route('/account/info')
@login_required
def accountInfo():
	return render_template('account-info.html')

@app.route('/account/security')
@login_required
def accountSecurity():
	return render_template('account-security.html')

@app.route('/account/connected-sites')
@login_required
def accountSites():
	return render_template('account-sites.html')

@app.route('/updates')
def updates():
	cur.execute('SELECT * FROM updates')
	result = cur.fetchall()

	#title = result[0]
	#text = result[1]
	#popup = result[2]
	#popuptext = result[3]
	#date = result[4]

	#if popup == 'on':
	#	popup = True

	#else:
	#	popup = False
	
	return render_template('updates.html', result=result)

@app.route('/admin/post-update', methods=['GET', 'POST'])
@login_required
def adminPostUpdate():
	if request.method == 'POST':
		title = request.form['title']
		text = request.form['text']
		popup = request.form.get('popupValue')
		if popup == 'on':
			popup = True
			popupText = request.form['popupText']

			try:
				cur.execute('INSERT INTO updates (title, text, popup, popuptext)' 'VALUES (%s, %s, %s, %s)', (format(title), format(text), format(popup), format(popupText)))
				conn.commit()
				return redirect(url_for('updates'))
			
			except Error as e:
				print(e)
				return redirect(url_for('error', e=e))
		else:
			popup = False
			popupText = None

			try:
				cur.execute('INSERT INTO updates (title, text)' 'VALUES (%s, %s)', (format(title), format(text)))
				conn.commit()
				return redirect(url_for('updates'))
			
			except Error as e:
				print(e)
				return redirect(url_for('error', e=e))

	else:
		userRole = checkUserRole()
		if userRole == 'admin':
			return render_template('create-post.html')
		
		else:
			flash('Non hai il permesso di accedere a questa pagina.', category='error')
			return redirect(url_for('root'))

@app.route('/policies/termini-di-servizio2023')
def tds():
	return "termini di servizio leotecno.tk..."

@app.route('/error')
def error():
	error = request.args.get('e')
	return render_template('global-error.html', error=error)

@app.route('/login-test')
@login_required
def logintest():
	return f"Questa è una pagina protetta. Benvenuto, {current_user.id}!"

if __name__ == '__main__':
	app.run(host='0.0.0.0', port=80, debug=True)
