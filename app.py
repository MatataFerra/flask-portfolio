import os
import datetime
import re
import base64
from time import timezone
from urllib.parse import urlencode
from requests import Request, post, get

import jwt

from dotenv import load_dotenv
import requests
from werkzeug.datastructures import Headers
load_dotenv()

from flask import Flask, request, jsonify, Response, make_response, session
from flask_cors import CORS
from flask_pymongo import PyMongo
from bson import json_util
from werkzeug.security import generate_password_hash, check_password_hash

from functools import wraps


app = Flask(__name__)
CORS(app)
app.config['MONGO_URI'] = f'{os.getenv("MONGO_URI")}'
app.config['SECRET_KEY'] = f'{os.getenv("SECRET_KEY")}'

mongo = PyMongo(app)

db = mongo.db.users
db_comment = db.comment
regex = "^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$"

def token_required(f):
  """ Verify if user has a valid token """
  @wraps(f)
  def decoreted(*args, **kwargs):
    token = request.args.get('token') or request.headers.get('x-token')

    if not token:
      return jsonify({'message': 'Token is missing'}), 403

    try:
      data = jwt.decode(token, app.config['SECRET_KEY'])
    except:
      return jsonify({'message': 'Token is invalid'}), 403

    return f(*args, **kwargs)
  return decoreted

@app.route('/api/v1/users', methods=["POST"])
def create_user():
  """ Recibiendo datos para la creación del usuario"""
  username = request.json['username']
  admin = request.json['admin']
  password = request.json['password']
  email = request.json['email']
  is_admin = request.json['is_admin']

  email_regex = re.match(regex, email)

  if admin != os.getenv("SECRET_ADMIN"):
    response = jsonify({
      'message': 'No tiene permisos para crear un usario, contactese con el administrador',
      'data': None,
      'status': 'error',
    })

    response.status_code = 404
    return response

  if not email_regex:
    response = jsonify({
      'message': 'El email que ingresó es incorrecto',
      'data': None,
      'status': 'error',
    })

    response.status_code = 404
    return response

  if username and email and password:
    hashed_password = generate_password_hash(password)
    id = db.insert_one(
      {
        'username': username,
        'email': email,
        'password': hashed_password,
        'isAdmin': is_admin or False
      }
    )

    response = jsonify({
      'message': 'User created succesuffuly check credentials with the administrator',
      'data': {
        'username': username,
        'email': email,
      },
      'status': 'ok'
    })

    response.status_code = 200

    return response
  else:
    return not_found()

@app.route('/api/v1/comments', methods=["GET"])
@token_required
def get_comments():
  comments = db_comment.find()
  response = json_util.dumps(comments)
  return Response(response, mimetype='application/json')

@app.route('/api/v1/comments', methods=["POST"])
def create_comments():
  client_name = request.json['client_name']
  client_email = request.json['client_email']
  client_comment = request.json['client_comment']
  client_phone = request.json['client_phone']

  id = db_comment.insert_one(
    {
      'username': client_name,
      'email': client_email,
      'comment': client_comment,
      'phone': client_phone,
      'time_stamp': datetime.datetime.now().strftime("%d-%m-%Y")
    }
  )
  if client_name and client_email and client_comment:
    response = jsonify({
      'message': 'Comment created succesuffuly, Congrats!',
      'data': {
        'Comment': client_comment
      },
      'status': 'ok'
    })

    response.status_code = 200

    return response
  else:
    return key_error()


@app.errorhandler(400)
def not_found(error=None):
  response = jsonify({
    'message': f'Resource not found: {request.url}',
    'status': 'error'
  })

  response.status_code = 400

  return response

@app.errorhandler(KeyError)
def key_error(error=None):
  response = jsonify({
    'message': 'No introdujo todos los campos, debe contactarse con el administrador',
    'status': 'error',
    'data': None
  })
  response.status_code = 404

  return response



@app.route('/api/v1/', methods=["POST"])
def login():
  username = request.json['username']
  admin = request.json['admin']
  password = request.json['password']
  email = request.json['email']

  if admin != os.getenv("SECRET_ADMIN"):
    response = jsonify({
      'message': 'No tiene permisos para crear un usario, contactese con el administrador',
      'status': 'error',
      'data': None
    })

    response.status_code = 404
    return response

  user = db.find_one({'email': email})

  is_admin = user['is_admin']

  if not is_admin:
    return key_error()

  check_password = check_password_hash(user['password'], password)

  print(check_password)

  if check_password:
    token = jwt.encode({'user': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)}, app.config['SECRET_KEY'])
    return jsonify({
      'token': token.decode('UTF-8'),
      'user': user['email']
    })
  
  return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})


# Spotify API



spotify_get_uri = "https://accounts.spotify.com/authorize"
client_id = os.getenv("CLIENT_ID")
client_secret = os.getenv("CLIENT_SECRET")
redirect_uri = os.getenv("REDIRECT_URI")
response_type="code"
scope="user-read-private"

url = Request('GET','https://accounts.spotify.com/authorize', params={
  'scope': scope,
  'response_type': response_type,
  'redirect_uri':redirect_uri,
  'client_id': client_id
}).prepare().url


@app.route('/', methods=["GET"])
def login_spotify():

  get_error_request = request.args.get('error')

  if get_error_request:
    return jsonify({
      'message': "An error has ocurred with the url",
      'status': 'error',
      'data': None
    })

  return jsonify({'url': url})

@app.route('/api/v1/spotify/auth', methods=["GET"])
def home():

  get_code_request = request.args.get('code')
  get_error_request = request.args.get('error')

  if get_error_request:
    return jsonify({
      'message': "An error has ocurred with de Authorization",
      'status': 'error',
      'data': None
    })
  client_cred = f"{client_id}:{client_secret}"
  client_cred_base64 = base64.b64encode(client_cred.encode())
  authorization_header = f'Basic {client_cred_base64.decode()}'

  response = post("https://accounts.spotify.com/api/token", data={
      "grant_type": "authorization_code",
      "code": get_code_request,
      "redirect_uri": redirect_uri
  }, headers={
    'Authorization': authorization_header
  }).json()

  access_token = response.get('access_token')
  token_type = response.get('token_type')
  refresh_token = response.get('refresh_token')
  expires_in = response.get('expires_in')
  error = response.get('error')

  if not 'spotify' in session:
    session['spotify'] = access_token

  return jsonify({
    'access_token': access_token,
    'token_type': token_type,
    'refresh_token': refresh_token,
    'expires_in': expires_in,
    'error': error
  },{'message': 'ok'}), 200

@app.route('/api/v1/spotify/search/<query>', methods=["GET"])
def search_spotify(query):
  endpoint = 'https://api.spotify.com/v1/search'
  # access_token = request.headers.get('Authorization')
  access_token = session['spotify']
  print(access_token)
  headers = {
    'Authorization': f"Bearer {access_token}"
  }

  data = urlencode({'q': query, "type": "track"})

  lookup_url = f"{endpoint}?{data}"
  response = get(lookup_url, headers=headers)

  if not response:
    return jsonify({
      'error': response.json()
    })

  response.status_code = 200
  return jsonify({
    'data': response.json()
  })


if __name__ == '__main__':
  app.run(debug=True)
