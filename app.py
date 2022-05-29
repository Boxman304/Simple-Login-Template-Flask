import datetime
import jwt

from flask import Flask
from flask import request
from flask import jsonify
from flask import abort
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_bcrypt import Bcrypt
SECRET_KEY = "b'|\xe7\xbfU3`\xc4\xec\xa7\xa9zf:}\xb5\xc7\xb9\x139^3@Dv'"

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] ='mysql+pymysql://root:unitrends1@localhost:3306/user_schema'
ma = Marshmallow(app)
bcrypt = Bcrypt(app)
CORS(app)
db = SQLAlchemy(app)
from Models.user import User, UserSchema
user_schema = UserSchema()
def create_token(user_id):
    payload = {
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=4),
        'iat': datetime.datetime.utcnow(),
        'sub': user_id
    }
    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm='HS256'
    )
def extract_auth_token(authenticated_request):
    auth_header = authenticated_request.headers.get('Authorization')
    if auth_header:
        return auth_header.split(" ")[1]
    else:
        return None
def decode_token(token):
    payload = jwt.decode(token, SECRET_KEY, 'HS256')
    return payload['sub']
@app.route('/user', methods=['POST'])
def user():
    _user = User(request.json['user_name'], request.json['password'])
    db.session.add(_user)
    db.session.commit()
    return jsonify(user_schema.dump(_user))


@app.route('/authentication', methods=['POST'])
def authenticate():
    if request.json['user_name'] is None or request.json['password'] is None:
        abort(400)

    user_auth = User.query.filter_by(user_name=request.json['user_name']).first()
    if not user_auth:
        abort(403)

    if not bcrypt.check_password_hash(user_auth.hashed_password, request.json['password']):
        abort(403)

    token = create_token(user_auth.id)
    return jsonify(token=token)    
# @app.route('/hello', methods=['GET']) #Used in Testing
# def hello_world():
#     return "Hello World!"
