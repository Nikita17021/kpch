import os

from flask_wtf import FlaskForm
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, send_file, url_for, flash, session, redirect, jsonify
from flask_sqlalchemy import SQLAlchemy
from azure.storage.blob import BlobServiceClient
from azure.storage.queue import QueueServiceClient, QueueClient
import io

from wtforms.fields.simple import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length

app = Flask(__name__, template_folder='.')
app.config['SECRET_KEY'] = 'nikita'


AZURE_STORAGE_CONNECTION_STRING = "DefaultEndpointsProtocol=https;AccountName=lab106125241656;AccountKey=wpKRejqkY3k+oTlzH556t2raC+PVyr/xAoTIlP7FfUKMn3Dr8+OhS/745WD4StkdEh9BIl1jKgHv+AStaS8DBg==;EndpointSuffix=core.windows.net"
AZURE_CONTAINER_NAME = "uploads"


AZURE_STORAGE_QUEUE_CONNECTION_STRING = "DefaultEndpointsProtocol=https;EndpointSuffix=core.windows.net;AccountName=projektchmury;AccountKey=DNaPSiZ02BmwzfTri/osfd47RNlUX4FMTXxzGfGvr4Vqlsdc8zc2j+P0ta5G2hyfIlILCOrRvFca+ASt2pKJwg==;BlobEndpoint=https://projektchmury.blob.core.windows.net/;FileEndpoint=https://projektchmury.file.core.windows.net/;QueueEndpoint=https://projektchmury.queue.core.windows.net/;TableEndpoint=https://projektchmury.table.core.windows.net/"
AZURE_QUEUE_NAME = "chmury"

app.config['SQLALCHEMY_DATABASE_URI'] = (
    'mssql+pyodbc://nikita_17021:Dream3871332@projektkpch.database.windows.net/projectkpch'
    '?driver=ODBC+Driver+17+for+SQL+Server'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class DownloadedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f"<DownloadedFile {self.filename}>"
class QueueMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f"<QueueMessage {self.content}>"

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('files', lazy=True))

    def __repr__(self):
        return f"<File {self.filename}>"

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

    def __repr__(self):
        return f"<User {self.username}>"

with app.app_context():

    db.create_all()

def create_azure_container_if_not_exists(container_name):
    blob_service_client = BlobServiceClient.from_connection_string(AZURE_STORAGE_CONNECTION_STRING)
    try:
        container_client = blob_service_client.create_container(container_name)
    except Exception as e:

        pass

create_azure_container_if_not_exists(AZURE_CONTAINER_NAME)

def create_azure_queue_client():
    return QueueClient.from_connection_string(AZURE_STORAGE_QUEUE_CONNECTION_STRING, AZURE_QUEUE_NAME)



def upload_file_to_azure_storage(file):
    blob_service_client = BlobServiceClient.from_connection_string(AZURE_STORAGE_CONNECTION_STRING)
    container_client = blob_service_client.get_container_client(AZURE_CONTAINER_NAME)

    filename = secure_filename(file.filename)
    blob_name = f"{os.urandom(24).hex()}_{filename}"

    blob_client = container_client.get_blob_client(blob_name)
    blob_client.upload_blob(file.stream.read())


    queue_client = create_azure_queue_client()
    queue_client.send_message(f"Upload: {blob_name}")


    new_message = QueueMessage(content=f"Upload: {blob_name}")
    db.session.add(new_message)
    db.session.commit()

    return blob_name

def download_file_from_azure_storage(blob_name):
    blob_service_client = BlobServiceClient.from_connection_string(AZURE_STORAGE_CONNECTION_STRING)
    container_client = blob_service_client.get_container_client(AZURE_CONTAINER_NAME)
    blob_client = container_client.get_blob_client(blob_name)


    file_stream = blob_client.download_blob().readall()


    downloaded_file = DownloadedFile(filename=blob_name)
    db.session.add(downloaded_file)
    db.session.commit()


    queue_client = create_azure_queue_client()
    queue_client.send_message(f"Download: {blob_name}")


    new_message = QueueMessage(content=f"Download: {blob_name}")
    db.session.add(new_message)
    db.session.commit()

    return file_stream


@app.route('/')
def index():
    if 'username' in session:
        current_user = User.query.filter_by(username=session['username']).first()
        user_container_name = f"{AZURE_CONTAINER_NAME}_{current_user.id}"
        create_azure_container_if_not_exists(user_container_name)
        blobs = [blob.filename for blob in current_user.files]
        return render_template('index.html', files=blobs)
    return redirect(url_for('login'))



@app.route('/download_file')
def downloaded_files():
    downloaded_files = DownloadedFile.query.all()
    return render_template('download_file.html', downloaded_files=downloaded_files)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        new_user = User(username=form.username.data, password=form.password.data)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully. You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.password == form.password.data:
            session['username'] = user.username
            flash('Login successful.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login unsuccessful. Please check your username and password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/api/files/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'No file part', 400

    file = request.files['file']

    if file.filename == '':
        return 'No selected file', 400

    try:

        blob_name = upload_file_to_azure_storage(file)

        current_user = User.query.filter_by(username=session['username']).first()
        new_file = File(filename=blob_name, user=current_user)
        db.session.add(new_file)
        db.session.commit()

        download_url = url_for('download_file', blob_name=blob_name, _external=True)

        return f'<a href="/">Home Back</a>  File uploaded successfully. Download link: <a href="{download_url}">{download_url}</a>', 200
    except Exception as e:
        print(str(e))
        return 'Error uploading file', 500

@app.route('/api/files/download/<blob_name>', methods=['GET'])
def download_file(blob_name):
    try:

        file_stream = download_file_from_azure_storage(blob_name)
        return send_file(io.BytesIO(file_stream), as_attachment=True, download_name='downloaded_file.txt', mimetype='text/plain')
    except Exception as e:
        print(str(e))
        return 'Error downloading file', 500

@app.route('/process_queue', methods=['GET'])
def process_queue():
    try:
        queue_client = create_azure_queue_client()
        messages = queue_client.receive_messages()

        processed_messages = []
        for message in messages:

            print(f"Processing message: {message.content}")
            processed_messages.append(message.content)

            queue_client.delete_message(message.id, message.pop_receipt)

        return jsonify({'status': 'success', 'messages': processed_messages})
    except Exception as e:
        return jsonify({'status': 'error', 'error_message': str(e)})

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

if __name__ == '__main__':
    app.run()
