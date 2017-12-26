#!/usr/bin/env python3

#todo 									FIX THIS BLYAD'PIZDETS!
#todo add SSL support or fuck it?
#todo add internationalization
#todo fix double logging
#todo if user is authorized he wshould go from root to someStuff immediatly
import datetime
import flask
import jwt
import json
import bson
import bson.json_util
import base64
import MongoDBTalker
from Entities import Config, User

apiVer = '/api/1.0'

app = flask.Flask(__name__)
cfg = Config('config.yml')
db = MongoDBTalker.MongoDBTalker(cfg.getDbHost(), cfg.getDbUser(), cfg.getDbPass(), cfg.getDbName())

### error handling

###need to get Request and check matching with exists routes instead write handler for every error
@app.errorhandler(400)
def page_not_found(error):
    return makeResponse(400, {})

@app.errorhandler(404)
def page_not_found(error):
    return makeResponse(404, {})

@app.errorhandler(405)
def page_not_found(error):
    return makeResponse(405, {})

### service methods

def toJSON(payload):
	return bson.json_util.dumps(payload)

def makeResponse(responseCode, responsePayload):
	# response = flask.Response(status = responseCode, mimetype = 'application/json', response = toJSON(responsePayload))
	# response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
	# response.headers['Pragma'] = 'no-cache'
	# response.headers['Expires'] = '0'
	# response.headers['Cache-Control'] = 'public, max-age=0'
	# print(response.headers)
	return flask.Response(status = responseCode, mimetype = 'application/json', response = toJSON(responsePayload))

def isCredentialsValid():
	result = False 

	if flask.request.is_json:
		username = flask.request.get_json().get('username')
		password = flask.request.get_json().get('password')

		if db.validateUser(username, password):
			return True
	# else:
	# 	raise Exception('request not contain JSON.')

	return result

def makeJWT():
	userId = str(db.getUser(flask.request.get_json().get('username')).get('_id'))
	expTime = str(datetime.datetime.now() + datetime.timedelta(seconds = 3600))
	return jwt.encode({'userId': userId, 'expTime': expTime}, cfg.getSecret(), algorithm = 'HS256')

def JWTUserInnerCheck(encryptedToken):
	result = {'result': False, 'username': None}

	try:
		decryptedToken = jwt.decode(encryptedToken, cfg.getSecret(), algorithms=['HS256'])
		# print(decryptedToken)
		if isinstance(decryptedToken, dict):
			expTime = decryptedToken.get('expTime')
			userId = decryptedToken.get('userId')
			if datetime.datetime.strptime(expTime, '%Y-%m-%d %H:%M:%S.%f') > datetime.datetime.now():
				if db.isUserExists(bson.objectid.ObjectId(userId)):
					result.update({'result': True, 'username': db.getUser(bson.objectid.ObjectId(userId)).get('name')})
			else:
				pass
		else:
			pass
	except Exception:
		pass

	return result

def isJWTValid(): #through header
	result = {'result': False, 'username': None}

	# if 'Authorization' in flask.request.headers.keys():
	# 	rawValue = flask.request.headers.get('Authorization')
	# 	# print(rawValue)
	# 	splittedValue = rawValue.split()
	# 	# print(splittedValue)
	# 	if len(splittedValue) == 2 and splittedValue[0] == 'Bearer' and splittedValue[1] != 0:
	# 		encryptedToken = splittedValue[1]
	# 		tempResult = JWTUserInnerCheck(encryptedToken)
	# 		if tempResult.get('result'):
	# 			result.update({'result': True, 'username': tempResult.get('username')})
	# 	print('A ' + str(result))
			
	if flask.request.headers.get('Cookie') != None:
		# print(flask.request.headers)
		rawValue = flask.request.headers.get('Cookie')
		# print(rawValue)
		cookies = rawValue.split(';')
		for cookie in cookies:
			if '_tt' in cookie:
				encryptedToken = cookie.split('=')[1]
				tempResult = JWTUserInnerCheck(encryptedToken)
				if len(encryptedToken) != 0 and tempResult.get('result'):
					result.update({'result': True, 'username': tempResult.get('username')})
		print('C ' + str(result))

	return result

def getExpTime():
	rawValue = flask.request.headers.get('Cookie')
	cookies = rawValue.split(';')
	for cookie in cookies:
		if '_tt' in cookie:
			encryptedToken = cookie.split('=')[1]
			decryptedToken = jwt.decode(encryptedToken, cfg.getSecret(), algorithms=['HS256'])
			return decryptedToken.get('expTime')

### routing

# @app.route('/error')
# def error(errorCode):
# 	return makeResponse(errorCode, {'error': {'code': errorCode}})

# @app.route('/expTime')
# def expTime():
# 	if isJWTValid().get('result'):
# 		return makeResponse(200, {'expTime': getExpTime()})
# 	else:
# 		return makeResponse(450, {'error': 'wrong JWT'})

@app.route('/auth', methods = ['POST'])
def auth():
	# try:
		if isCredentialsValid():
			# print('JWT returned')
			return makeResponse(200, {'_tt': makeJWT().decode()}) 
		else:
			return makeResponse(200, {'error': 'Are you shure?'})
	# except Exception:
	# 	return makeResponse(200, {'error': 'Can\'t authenticate'})

@app.route('/')
def root():
	if isJWTValid().get('result'):
		return app.send_static_file('someStuff.html')
	else:
		return app.send_static_file('index.html')

@app.route('/someStuff')
def someStuff():
	if isJWTValid().get('result'):
		return app.send_static_file('someStuff.html')
	else:
		return makeResponse(450, {'error': 'wrong JWT'})

@app.route(apiVer + '/show/record/all')
def getAllRecords():
	if isJWTValid().get('result'):
		# print(db.getAllRecords())
		return makeResponse(200, {'records': db.getAllRecords()})
	else:
		return makeResponse(450, {'error': 'wrong JWT'})


@app.route(apiVer + '/show/record/<recordId>')
def getRecordById(recordId):
	if isJWTValid().get('result'):
		return makeResponse(200, db.getRecord(bson.objectid.ObjectId(recordId)))
	else:
		return makeResponse(450, {'error': 'wrong JWT'})

# def JWTValidation(method):
# 	def wrapperMethod():
# 		if isJWTValid().get('result'):
# 			method()
# 		else:
# 			return makeResponse(450, {'error': 'wrong JWT'})
# 	return wrapperMethod

@app.route(apiVer + '/add/record', methods = ['POST'])
def addRecord():
# @JWTValidation
	if isJWTValid().get('result'): 
# def addRecord():
		try:
			request = flask.request.get_json()
			db.createRecord(
				request.get('recordName'), 
				request.get('serverAddress'), 
				request.get('username'), 
				request.get('password'), 
				url = request.get('url'), 
				notes = request.get('notes')
				)
			return makeResponse(200, {'result': 'success'})
		except Exception:
			return makeResponse(200, {'result': 'error'})
	else:
		return makeResponse(450, {'error': 'wrong JWT'})

@app.route(apiVer + '/update/record', methods = ['POST'])
def editRecord():
	if isJWTValid().get('result'):
		try:
			request = flask.request.get_json()
			db.updateRecord(
				bson.objectid.ObjectId(request.get('recordId')), 
				ame = request.get('recordName'), 
				serverAddress = request.get('serverAddress'), 
				username = request.get('username'), 
				password = request.get('password'), 
				url = request.get('url'), 
				notes = request.get('notes'), 
				modificationDate = datetime.datetime.utcfromtimestamp(request.get('modificationDate') / 1e3))
			return makeResponse(200, {'result': 'success'})
		except Exception:
			return makeResponse(200, {'result': 'error'})
	else:
		return makeResponse(450, {'error': 'wrong JWT'})

@app.route(apiVer + '/delete/record/<recordId>')
def deleteRecord(recordId):
	if isJWTValid().get('result'): 
		try:
			# request = flask.request.get_json()
			db.deleteRecord(bson.objectid.ObjectId(recordId))
			return makeResponse(200, {'result': 'success'})
		except Exception:
			return makeResponse(200, {'result': 'error'})
	else:
		return makeResponse(450, {'error': 'wrong JWT'})




# @app.route(apiVer + '/')
# def apiRoot(): 
# 	# return makeResponse(200, flask.request.headers)
# 	if isCredentialsValid() == True:
# 		return makeResponse(200, 'you have been authorized')
# 	else:
# 		return makeResponse(400, 'sorry. no such user.')

# @app.route(apiVer + 'groups')
# def getGroups():
# 	# return makeResponse(200, {'groups': db.getAllGroups()})
# 	if isCredentialsValid() == True:
# 		return makeResponse(200, {'groups': db.getAllGroups()})
# 	else:
# 		return makeResponse(400, 'sorry. no such user.')

# @app.route(apiVer + 'group/<groupname>')
# def getGroup(groupname):
# 	return makeResponse(200, db.getGroup(groupname))

# @app.route(apiVer + 'users')
# def getUsers():
# 	return makeResponse(200, {'users': db.getAllUsers()})

# @app.route(apiVer + 'user/<username>')
# def getUser(username):
# 	return makeResponse(200, {'users': db.getUser(username)})

# @app.route(apiVer + 'catalogs')
# def getCatalogs():
# 	return makeResponse(200, {'catalogs': db.getAllCatalogs()})

# @app.route(apiVer + 'records')
# def getRecords():
# 	return makeResponse(200, {'records': db.getAllRecords()})

### some other shit

if __name__ == '__main__':
	app.run(debug = True)
	# print(normalize(db.getAllGroups()))