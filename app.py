
from flask import Flask, render_template

app = Flask(__name__, template_folder='.', static_folder='static')

app.config['SECRET_KEY'] = 'nikita'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/yes')
def yes_page():
    return render_template('yes.html')

if __name__ == '__main__':
    app.run()
