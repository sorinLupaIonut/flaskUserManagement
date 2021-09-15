from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import os
from flask_restful import Resource, Api, abort , reqparse

app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)
    address = db.Column(db.String(200))
    email = db.Column(db.String(100))





def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401
        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated





@app.route('/getUsers', methods=['GET'])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})
    users = User.query.all()
    output = []
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        user_data['address'] = user.address
        user_data['email'] = user.email
        output.append(user_data)
    return jsonify({'users' : output})






@app.route('/signUp', methods=['POST'])
def create_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=True)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message' : 'New user created!'})



@app.route('/edit', methods=['PUT'])
@token_required
def edit_user(current_user):
    data = request.get_json()
    user = User.query.filter_by(public_id=current_user.public_id).first()
    if not user:
        return jsonify({'message' : 'No user found!'})
    if data['address']:
        user.address = data['address']    
    if data['email']:
        user.email = data['email']    
    db.session.commit()
    return jsonify({'message' : 'The user has been updated!'})



@app.route('/changePassword', methods=['PUT'])
@token_required
def changePassword(current_user):
    data = request.get_json()
    user = User.query.filter_by(public_id=current_user.public_id).first()
    if not user:
        return jsonify({'message' : 'No user found!'})
    if check_password_hash(user.password, data['oldPassword']) == False:
        return jsonify({'message' : 'Old password is not correct!'})
    if data['newPassword'] != data['newPasswordRetype']:
        return jsonify({'message' : 'New password is not equal to newPasswordRetype!'})  
    hashed_password = generate_password_hash(data['newPassword'], method='sha256')    
    user.password = hashed_password   
    db.session.commit()
    return jsonify({'message' : 'The password has been changed!'})   




@app.route('/signIn')
def signIn():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
    user = User.query.filter_by(name=auth.username).first()
    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'token' : token.decode('UTF-8')})
    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})






if __name__ == '__main__':
    if not os.path.exists('db.sqlite'):
        db.create_all()
    app.run(debug=True)