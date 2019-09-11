from flask import Flask, jsonify, request
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'BIZE HER YER TRABZON'

@app.route('/')
def test():
    return "test"


def auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            token = kwargs['token']
        except:
            token = request.args.get('token') or \
                    request.form.get('token')

        if not token:
            return jsonify({'message': 'Token required!'}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])

        except:
            return jsonify({'message': 'Token invalid!'}), 403

        return f(*args, **kwargs)

    return wrapper


@app.route('/api/v1/user/<token>', methods=['GET'])
@auth
def user(token):
    message = 'Token is validate'
    return jsonify({'message': message})


@app.route('/api/v1/comment/<token>', methods=['POST'])
@auth
def comment(token):
    comment = request.form.get('comment')

    return "SUCCESS"

@app.route('/api/v1/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')

    token = ''
    if username == 'test' and password == 'admin':
        token = jwt.encode({
            'user': username,
            'password': password,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        }, app.config['SECRET_KEY'])
    else:
        token = 'Invalid username or password'

    return jsonify({'message': 'You registered!', 'token': token.decode('UTF-8')})


if __name__ == '__main__':
    app.run( debug=True)




