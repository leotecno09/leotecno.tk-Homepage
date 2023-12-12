# IMPORTAZIONE MODULI
from flask import Flask, render_template, flash, url_for, request, redirect, jsonify, Response
from flask_bootstrap import Bootstrap
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, date
from functools import wraps
import psycopg2																	
from psycopg2 import Error
import os
import random
import flask_login
import secrets
#import pyotp
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

# VARIABLES
LOGO_FOLDER = 'Q:/Workstation/leotecnotk-new-homepage/static/images/accounts/uploaded'
ALLOWED_LOGO_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# FLASK THINGS
app = Flask(__name__)
Bootstrap(app)

#bcrypt = Bcrypt(app)

# FLASK CONFIGURATIONS
app.config['SECRET_KEY'] = 'dasiugdjfr7h5g5'
app.config['LOGO_FOLDER'] = LOGO_FOLDER

#FLASK MAIL
app.config['MAIL_SERVER'] = 'live.smtp.mailtrap.io'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'xxx'
app.config['MAIL_PASSWORD'] = 'xxxxxxxxxxxxxxxxxxxxxxxxx'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)

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
		logoPath = result[7]
	
		user = User(id)
		user.username = username
		user.email = email
		user.logo = logoPath
		return user
	
	except Error as e:
		return redirect(url_for('error'))
	#return "Ciao"

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

def chooseLogo(username):
		letter = username[0]
		letter = letter.upper()
		print(letter)
		logoDir = "Q:/Workstation/leotecnotk-new-homepage/static/images/accounts/letters"
		dirProvv = '/static/images/accounts/letters'
				
		logos = os.listdir(logoDir)

		logo = [file for file in logos if file.startswith(letter)]
		fileName = logo[0]
		logoPath = f"{dirProvv}/{fileName}"
		
		return logoPath

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_LOGO_EXTENSIONS

# ERROR HANDLER
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# ROUTES
@app.route('/')
def root():
	user_agent = request.headers.get('User-Agent', '')
	is_smartphone = any(keyword in user_agent for keyword in ['Mobile', 'Android', 'iPhone', 'iPad'])

	if is_smartphone:
		return render_template('mobilewarn.html')
	else:
		return render_template('index.html')
	
@app.route('/n')
def homeNoCheck():
	user_agent = request.headers.get('User-Agent', '')

	is_desktop = not any(keyword in user_agent for keyword in ['Mobile', 'Android', 'iPhone', 'iPad'])

	if is_desktop:
		return redirect(url_for('root'))
	
	else:
		return render_template('index.html')

@app.route('/account/register', methods=['GET', 'POST'])
def register():
	if request.method == 'POST':
		# DAL FORM
		username = request.form['name']
		email = request.form['email']
		password = request.form['password']
		passwordConfirm = request.form['passwordConfirm']
		checkbox = request.form.get('checkbox') == 'true'
		print(checkbox)

		# CREATE LATO SERVER
		now = datetime.now()
		formatted_datetime = now.strftime("%d/%m/%Y %H:%M:%S")

		creation_date = formatted_datetime

		userID = ''.join([str(random.randint(0, 9)) for _ in range(9)])

		logoPath = chooseLogo(username)

		try:
			cur.execute('SELECT * FROM accounts WHERE email = %s', (email,))
			result = cur.fetchone()

			if result:
				result = "error"
				popup_text = "Account già esistente."

				return jsonify({"result": result, "popup_text": popup_text})

			elif password != passwordConfirm:
				result = "error"
				popup_text = "Le due password non corrispondono."

				return jsonify({"result": result, "popup_text": popup_text})

			elif len(password) < 7:
				result = "error"
				popup_text = "La password deve contenere almeno 7 caratteri."

				return jsonify({"result": result, "popup_text": popup_text})

			elif not checkbox:
				result = "error"
				popup_text = "Per favore, accetta i termini di servizio."

				return jsonify({"result": result, "popup_text": popup_text})

			else:									
				hashed_password = generate_password_hash(password, method='scrypt')

				try:
					cur.execute('INSERT INTO accounts (username, email, password, id, created_on, logo)' 'VALUES (%s, %s, %s, %s, %s, %s)', (format(username), format(email), format(hashed_password), int(userID), format(creation_date), format(logoPath)))
					conn.commit()

					user = User(id=userID)
					user.username = username
					user.email = email
					user.logo = logoPath
					login_user(user, remember=True)
					result = "success"

					return jsonify({"result": result})

				except Error as e:
					return redirect(url_for('error', e=e))
				
		except Error as e:
			return redirect(url_for('error', e=e))			
	
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
				logoPath = result[7]
				two_step = result[8]
				print(two_step)
				#print (format(stored_password), format(password))
				
				if check_password_hash(stored_password, password):
					if two_step == "TRUE":
						token = secrets.token_hex()
						login_code = ''.join([str(random.randint(0, 9)) for _ in range(6)])

						message = Message (
							subject = 'Codice di autenticazione - Verifica in due passaggi leotecno.tk',
							recipients = [email],
							sender = 'security@leotecno.tk'						
						)

						message.body = f"Ecco il tuo codice di autenticazione per la verifica in due passaggi: {login_code}"

						try:
							mail.send(message)
							print("[SECURITY] TwoSteps email sended!")

							# QUERY FOR DB
							cur.execute('INSERT INTO login_codes (token, code)' 'VALUES (%s, %s)', (format(token), int(login_code),))
							conn.commit()

							#params = {'token': token, 'user_id': user_id}
							#redirect_url = url_for('twoStepVerification')
							return jsonify({'redirect': f'/account/login/twostepsverification?token={token}&user_id={user_id}'})	# SOSTITUIRE CON AJAX	
						
						except Error as e:
							return redirect(url_for('error', e=e))

					else:
						user = User(id=user_id)
						user.username = usernameFromDB
						user.email = email
						user.logo = logoPath
						login_user(user, remember=True)
						#flash("Autenticato con successo.")
						result = "success"
						return jsonify({"result": result})
				
				else:
					result = "error"
					popup_text = "Password errata."

					return jsonify({"result": result, "popup_text": popup_text})


			else:
				result = "error"
				popup_text = "Username errato o account inesistente."

				return jsonify({"result": result, "popup_text": popup_text})

		except Error as e:
			return redirect(url_for('error', e=e))
	else:	
		return render_template('login.html')
	
@app.route('/account/login/twostepsverification', methods=['GET', 'POST'])
def twoStepVerification():
	if request.method == 'POST':
		token = request.form['token']
		user_id = request.form['user_id']
		#token = request.args.get('token')
		#user_id = request.args.get('user_id')
		code = request.form['code']
		#print(code)
		#print(token)
		#  print(user_id)

		cur.execute('SELECT * FROM login_codes WHERE token = %s', (token,))
		result = cur.fetchone()

		codeFromDB = result[1]
		print(codeFromDB)

		if int(code) == int(codeFromDB):
			cur.execute('SELECT * FROM accounts WHERE id = %s', (int(user_id),))
			result = cur.fetchone()

			usernameFromDB = result[0]
			email = result[1]
			logoPath = result[7]

			user = User(id=user_id)
			user.username = usernameFromDB
			user.email = email
			user.logo = logoPath
			login_user(user, remember=True)

			cur.execute('DELETE FROM login_codes WHERE token = %s', (token,))
			conn.commit()
			token = 0
			code = 0

			result = "success"
			return jsonify({'result': result})

		else:
			result = "error"
			popup_text = "Codice di autenticazione errato."
			return jsonify({'result': result, 'popup_text': popup_text})



	else:
		token = request.args.get('token')
		user_id = request.args.get('user_id')
		return render_template('2fa.html', token=token, user_id=user_id)
	

	
@app.route('/account/logout')
@login_required
def logout():
	logout_user()
	flash('Logout effettuato con successo.')
	return redirect(url_for('login'))

@app.route('/account/settings')
@login_required
def accountSettings():
	return render_template('account-settings.html')

@app.route('/account/info')
@login_required
def accountInfo():
	return render_template('account-info.html')

@app.route('/account/security')
@login_required
def accountSecurity():
	try:
		id = current_user.id
		cur.execute('SELECT * FROM accounts WHERE id = %s', (int(id),))
		result = cur.fetchone()

		two_steps = result[8]
		last_password_change = result[9]
		#flash("this is a simulation. this is not real. this is a test.")
		return render_template('account-security.html', two_steps=two_steps, last_password_change=last_password_change)
	
	except Error as e:
		return redirect(url_for('error', e=e))		

@app.route('/account/connected-sites')
@login_required
def accountSites():
	return render_template('account-sites.html')

	
@app.route('/account/danger-zone')
@login_required
def accountDanger():
	return render_template('account-danger.html')

@app.route('/account/actions/changePassword', methods=['POST'])
def changePassword():
	currentPassword = request.form['currentPassword']
	newPassword = request.form['newPassword']
	confirmNewPassword = request.form['confirmNewPassword']
	id = current_user.id

	# CHECK CURRENT PASSWORD
	try:
		cur.execute('SELECT * FROM accounts WHERE id = %s', (int(id),))
		result = cur.fetchone()
		
		stored_password = result[2]

		if check_password_hash(stored_password, currentPassword):
			
			if len(newPassword) < 7:
				result = "error"
				popup_text = "La password deve contenere almeno 7 caratteri."
				return jsonify({'result': result, 'popup_text': popup_text})
			
			else:

				if newPassword == confirmNewPassword:
					new_hashed_password = generate_password_hash(newPassword, method='scrypt')

					now = datetime.now()
					formatted_datetime = now.strftime("%d/%m/%Y %H:%M:%S")

					creation_date = formatted_datetime

					cur.execute('UPDATE accounts SET password = %s, last_password_change = %s WHERE id = %s', (format(new_hashed_password), format(creation_date), int(id)))
					conn.commit()

					#flash('Password aggiornata con successo.')
					result = "success"
					return jsonify({"result": result})

				else:
					#flash('Le due nuove password non corrispondono.', category='error')
					result = "error"
					popup_text = "Le due password non corrispondono."
					return jsonify({"result": result, "popup_text": popup_text})

		else:
				result = "error"
				popup_text = "La password corrente è errata."
				return jsonify({"result": result, "popup_text": popup_text})
	
	except Error as e:
		return redirect(url_for('error', e=e))
	
@app.route('/account/actions/changeUsername', methods=['POST'])
@login_required
def changeUsername():
	currentPassword = request.form['currentPassword']
	newUsername = request.form['newUsername']

	id = current_user.id

	try:
		cur.execute('SELECT * FROM accounts WHERE id = %s', (int(id),))
		result = cur.fetchone()

		logo_dir = result[7]
		stored_password = result[2]

		if "uploaded" in logo_dir:
			logoPath = logo_dir
		
		else:
			logoPath = chooseLogo(newUsername)

		if check_password_hash(stored_password, currentPassword):
			
			try:
				cur.execute('UPDATE accounts SET username = %s, logo = %s WHERE id = %s', (format(newUsername), format(logoPath), int(id)))
				conn.commit()

				#flash('Username aggiornato con successo.')
				result = "success"
				return jsonify({"result": result})
			
			except Error as e:
				return redirect(url_for('error', e=e))
		
		else:
			result = "error"
			popup_text = "Password errata."
			return jsonify({"result": result, "popup_text": popup_text})

	except Error as e:
		return redirect(url_for('error', e=e))
	
@app.route('/account/actions/changeEmail', methods=['POST'])
@login_required
def changeEmail():
	currentPassword = request.form['currentPassword']
	newEmail = request.form['newEmail']

	id = current_user.id

	try:
		cur.execute('SELECT * FROM accounts WHERE id = %s', (int(id),))
		result = cur.fetchone()

		stored_password = result[2]

		if check_password_hash(stored_password, currentPassword):
			
			try:
				cur.execute('UPDATE accounts SET email = %s WHERE id = %s', (format(newEmail), int(id)))
				conn.commit()

				result = "success"
				return jsonify({"result": result})
			
			except Error as e:
				return redirect(url_for('error', e=e))
		
		else:
			result = "error"
			popup_text = "Password errata."
			
			return jsonify({"result": result, "popup_text": popup_text})

	except Error as e:
		return redirect(url_for('error', e=e))



@app.route('/account/actions/enable2FA', methods=['POST'])
def enable2FA():
	password = request.form['password']
	id = current_user.id

	try:
		cur.execute('SELECT * FROM accounts WHERE id = %s', (int(id),))
		result = cur.fetchone()

		stored_password = result[2]

		if check_password_hash(stored_password, password):

			try:
				cur.execute("UPDATE accounts SET two_steps = 'TRUE' WHERE id = %s", (int(id),))
				conn.commit()

				#flash('Verifica in due passaggi attivata con successo.')
				risultato = "success"
				return jsonify({"risultato": risultato})
			
			except Error as e:
				return redirect(url_for('error', e=e))
			
		else:
			#flash('Password errata.', category='error')
			risultato = "error"
			popup_text = "Password errata."
			return jsonify({"risultato": risultato, "popup_text": popup_text})
	
	except Error as e:
		return redirect(url_for('error', e=e))
	
@app.route('/account/actions/disable2FA', methods=['POST'])
def disable2FA():
	password = request.form['password']
	id = current_user.id

	print(password)

	try:
		cur.execute('SELECT * FROM accounts WHERE id = %s', (int(id),))
		result = cur.fetchone()

		stored_password = result[2]

		if check_password_hash(stored_password, password):

			try:
				cur.execute("UPDATE accounts SET two_steps = '' WHERE id = %s", (int(id),))
				conn.commit()

				#flash('Verifica in due passaggi disattivata con successo.')
				result = "success"
				return jsonify({"result": result})
			
			except Error as e:
				return redirect(url_for('error', e=e))

		else:		
			#flash('Password errata.', category='error')
			result = "error"
			popup_text = "Password errata."
			return jsonify({"result": result, "popup_text": popup_text})
	
	except Error as e:
		return redirect(url_for('error', e=e))
	
@app.route('/account/actions/deleteAccount', methods=['POST'])
def delAccount():
	password = request.form['password']
	id = current_user.id

	try:
		cur.execute('SELECT * FROM accounts WHERE id = %s', (int(id),))
		result = cur.fetchone()
	
		stored_password = result[2]
	
		if check_password_hash(stored_password, password):
			result = "success"

			return jsonify({"result": result})
		
		else:
			result = "error"
			popup_text = "Password errata."

			return jsonify({"result": result, "popup_text": popup_text})
		
	except Error as e:
		return redirect(url_for('error', e=e))

@app.route('/hidden/deep/blowing_up_your_account', methods=['POST'])
def hiddenBlowUp():	
	return render_template('blowing_up_account.html')
	
@app.route('/account/actions/deleteAccount1', methods=['POST'])
def effettivoDelAccount():
	id = current_user.id

	try:
		logout_user()
		cur.execute('DELETE FROM accounts WHERE id = %s', (int(id),))
		conn.commit()

		result = "success"

		return jsonify({"result": result})

	except Error as e:
		return redirect(url_for('error', e=e))	

@app.route('/account/actions/changeLogo', methods=['POST'])
def changeLogo():
	username = str(current_user.username)
	id = current_user.id
	
	logo = request.files['logo']

	if logo.filename == '':
		result = "error"
		popup_text = "Seleziona un file."
		return jsonify({'result': result, 'popup_text': popup_text})
	
	if logo and allowed_file(logo.filename):
		filename = secure_filename(username + '.' + logo.filename.rsplit('.', 1)[1].lower())
		logoPath = '/static/images/accounts/uploaded/' + filename
		#print(logoPath)
		logo.save(os.path.join(app.config['LOGO_FOLDER'], filename))

		try:
			cur.execute('UPDATE accounts SET logo = %s WHERE id = %s', (format(logoPath), int(id)))
			conn.commit()

		except Error as e:
			return redirect(url_for('error', e=e))

		result = "success"
		return jsonify({'result': result})
	
	else:
		result = "error"
		popup_text = "Formato file non valido."
		return jsonify({'result': result, 'popup_text': popup_text})



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

@app.route('/admin/users-management', methods=['GET', 'POST'])
@login_required
def adminUserManagement():
	if request.method == 'POST':
		return "post"		

	else:
		userRole = checkUserRole()
		if userRole == 'admin':
			return render_template('user-management.html')
		
		else:
			flash('Non hai il permesso di accedere a questa pagina.', category='error')
			return redirect(url_for('root'))


@app.route('/policies/termini-di-servizio2023')
def tds():
	return render_template('tds2023.html')

@app.route('/error')
def error():
	error = request.args.get('e')
	return render_template('global-error.html', error=error)

#@app.route('/login-test')
#@login_required
#def logintest():
#	return f"Questa è una pagina protetta. Benvenuto, {current_user.id}!"

#@app.route('/send-me-mail')
#def sendmail():
#	message = Message(
#		subject = 'Hello from Flask',
#		recipients = ['leotecno09@gmail.com'],
#		sender = 'flask@leotecno.tk'
#	)
#
#	message.body = "Questo è un test."
#	
#	try:
#		mail.send(message)
#		print("Email di verifica inviata")
#		return 'OK'
#	
#	except Error as e:
#		return redirect(url_for('error', e=e))
	
@app.route('/test', methods=['GET', 'POST'])
def test():
	return 'Test page. Not in use.'

	

if __name__ == '__main__':
	app.run(host='0.0.0.0', port=80, debug=True)
