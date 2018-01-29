import pymongo
import inspect
import bson
import datetime
# import urllib.parse
import MD5Crypter
import PassGen
from Entities import Catalog, Group, Record, User, Config
from cryptography.fernet import Fernet

#todo need to return only groups in which user are take part OR deny getting all(users, groups, catalogs, records) for all users, only to admins
#todo need mace code more OO and use entity like gropObject, userObject instead use streight groupName, username etc. 
#todo need to add check for quantity of record's catalogs: only one must survive
#todo make limitation for creating names for user, group, catalog or record with special characters
#todo REALLY need exception handlers
#todo add email to User
#todo add favicon
#todo add time of creation and time f modification of record
#todo add import from KeePass

class MongoDBTalker:

	def __init__(self, serverAddress, username, password, dbName, serverPort=27017):
		self.serverAddress = serverAddress
		self.username = username
		self.password = password
		self.dbName = dbName
		self.serverPort = serverPort

		self.cfg = Config('config.yml')

		self.makeConnection()

	### Connection section ###

	def makeConnection(self):
		result = False
		try:
			self.talker = pymongo.MongoClient('mongodb://{}:{}/'.format(self.serverAddress, self.serverPort))
			self.db = self.talker[self.dbName]
			self.db.authenticate(self.username, self.password)

			# self.groups = self.db['groups']
			self.users = self.db['users']
			# self.catalogs = self.db['catalogs']
			self.records = self.db['records']
			# self.sessions = self.db['sessions']
			
			result = True
		except Exception as ex:
			print(ex)
		return result

	def closeConnection(self):
		self.talker.close()

	### Some internal cool stuff, you know ###

	def __oIH(self, identifier): #__objectIdentifierHandler
		if isinstance(identifier, str):
			return {'name': identifier}
		elif isinstance(identifier, bson.ObjectId):
			return {'_id': identifier}
		else:
			raise IllegalArgumentTypeException(identifier)

	### Various checks section ###

	# def __isCatalogExists(self, value): #now more OO
	# 	result = False
		
	# 	if self.catalogs.find_one(self.__oIH(value)) != None:
	# 		result = True

	# 	return result

	# def __isGroupExists(self, value): #now more OO
	# 	result = False

	# 	if self.groups.find_one(self.__oIH(value)) != None:
	# 		result = True

	# 	return result

	# def isRecordExists(self, value, catalogName): #now more OO
	# 	result = False

	# 	if self.__isCatalogExists(catalogName) and self.records.find_one({'$and':[self.__oIH(value), {'catalog.name': catalogName}]}) != None:
	# 		result = True

	# 	return result

	def isRecordExists(self, value): #now more OO
		result = False

		if self.records.find_one(self.__oIH(value)) != None:
			result = True

		return result

	def isUserExists(self, value): #now more OO
		result = False

		if self.users.find_one(self.__oIH(value)) != None:
			result = True

		return result


	def encryptPassword(self, plainTextPassword):
		crypter = Fernet(self.cfg.getSalt().encode())
		return bytes.decode(crypter.encrypt(str.encode(plainTextPassword)))

	def decryptPassword(self, encryptedPassword):
		crypter = Fernet(self.cfg.getSalt().encode())
		return bytes.decode(crypter.decrypt(str.encode(encryptedPassword)))

	# def __isUserInGroup(self, userValue, groupValue):
	# 	result = False

	# 	user = self.getUser(userValue)
	# 	group = self.getGroup(groupValue)

	# 	userGroups = self.getUserGroups(userValue) #refactor getUserGroups!!!!!!!!!!
			
	# 	for group in userGroups:
	# 		if self.groups.find_one({'name': group.get('name')}).get('name') == groupName:
	# 			result = True

	# 	return result

	# def __isGroupIsEmpty(self, groupName):
	# 	result = False

	# 	if self.__isGroupExists(groupName) and self.users.find({'groups':{'name': groupName}}).count() == 0:
	# 		result = True

	# 	return result

	# def __isLastGroupForUser(self, username):
	# 	result = False

	# 	if len(self.users.find_one({'name': username}).get('groups')) == 1:
	# 		result = True

	# 	return result	

	# def __isCatalogIsEmpty(self, catalogName):
	# 	result = False

	# 	if self.__isCatalogExists(catalogName) and self.records.find({'catalog': catalogName}).count() == 0:
	# 		result = True

	# 	return result

	# def __isGroupHaveAccessToCatalog(self, groupName, catalogName):
	# 	result = False

	# 	if self.__isGroupExists(groupName) and self.__isCatalogExists(catalogName):
	# 		catalogs = self.getGroupCatalogs(groupName)

	# 		for catalog in catalogs:
	# 			if catalog.get('name') == catalogName:
	# 				result = True

	# 	return result	

	### Create section ###  ??? should i add return value to this functions ???

	# def createGroup(self, groupName):
	# 	if not self.__isGroupExists(groupName):
	# 		self.groups.insert_one({'name': groupName, 'catalogs': []})
	# 	else:
	# 		raise Exception('group name "' + groupName + '" already exists.')

	def createUser(self, username, password):
		if not self.isUserExists(username):
			# if self.__isGroupExists(groupName):
				# self.users.insert_one({'name': username, 'password': MD5Crypter.MD5Crypter().getHash(password), 'groups':[self.getGroup(groupName)], 'apiToken': self.createApiToken(), 'temporalToken': ''})
				self.users.insert_one({'name': username, 'password': MD5Crypter.MD5Crypter().getHash(password), 'apiToken': self.createApiToken()})
			# else:
			# 	raise NoSuchGroupException(groupName)	
		else:
			raise Exception('can\'t create user. User "' + username + '" already exists.')

	# def createCatalog(self, catalogName):
	# 	if self.__isCatalogExists(catalogName) == False:
	# 		if catalogName != 'all':
	# 			self.catalogs.insert_one({'name': catalogName})
	# 		else:
	# 			raise Exception('you can not create catalog with that name: "' + catalogName + '".')
	# 	else:
	# 		raise Exception('catalog "' + catalogName + '" already exists.')

	def createRecord(self, recordName, serverAddress, username, password, url='', notes=''):
		# if self.__isCatalogExists(catalogName) == True:
			if self.isRecordExists(recordName) == False:
				# self.records.insert_one({'name': recordName, 'serverAddress': serverAddress, 'username': username, 'password': password, 'catalog': self.getCatalog(catalogName), 'url': url, 'notes': notes})
				self.records.insert_one({
					'name': recordName, 
					'serverAddress': serverAddress, 
					'username': username, 
					'password': self.encryptPassword(password), 
					'url': url, 
					'notes': notes, 
					'creationDate': datetime.datetime.utcnow(), 
					'modificationDate': datetime.datetime.utcnow()
					})
			else:
				raise Exception('can\'t create record. Record "' + recordName + '" already exists in this group.')	
		# else:
		# 	raise NoSuchCatalogException(catalogName)

	### Read section ###

	def _verifyResult(self, objectType, result, value):
		if type(result) == dict and len(result) > 0:
			return result
		# else:
		# 	if objectType == 'catalog':
		# 		raise NoSuchCatalogException(value)
		# 	elif objectType == 'group':
		# 		raise NoSuchGroupException(value)
		# 	elif objectType == 'record':
		# 		raise NoSuchRecordException(value)
		# 	elif objectType == 'user':
		# 		raise NoSuchUserException(value)

	# def getCatalog(self, value): #now more OO
	# 	result = self.catalogs.find_one(self.__oIH(value))

	# 	return self._verifyResult('catalog', result, value)

	# 	# catalog = self._verifyResult('catalog', self.catalogs.find_one(self.__oIH(value)), value)

	# 	# return Catalog(catalog.get('_id'), catalog.get('name'))

	# def getGroup(self, value): #now more OO
	# 	result = self.groups.find_one(self.__oIH(value))

	# 	return self._verifyResult('group', result, value)

	# 	# group = self._verifyResult('group', self.groups.find_one(self.__oIH(value)), value)

	# 	# catalogs = []
	# 	# for catalog in group.get('catalogs'):
	# 	# 	catalogs.append(self.getCatalog(catalog.get('name')))

	# 	# return Group(group.get('_id'), group.get('name'), catalogs)

	def getRecord(self, value): #now more OO 
		result = self.records.find_one(self.__oIH(value))

		tempResult = result.copy()
		tempResult['password'] = self.decryptPassword(result.get('password'))
		
		return self._verifyResult('record', tempResult, value)

		# record = self._verifyResult('record', self.groups.find_one(self.__oIH(value)), value)

		# return Record(record.get('_id'), record.get('name'), record.get('serverAddress'), record.get('username'), record.get('password'), record.get('serverAddress'), record.get('catalogName'), record.get('url'), record.get('notes'))

	def getUser(self, value): #now more OO
		result = self.users.find_one(self.__oIH(value))

		return self._verifyResult('user', result, value)

		# user = self._verifyResult('user', self.users.find_one(self.__oIH(value)), value)

		# groups = []
		# for group in user.get('groups'):
		# 	groups.append(self.getGroup(group.get('name')))

		# return User(user.get('_id'), user.get('name'), user.get('password'), groups, user.get('apiToken'))

	# def getAllGroups(self): #now more OO
	# 	rawResults = self.groups.find({})
	# 	results = []

	# 	for group in rawResults:
	# 		results.append(group)
	# 		# results.append(self.getGroup(group.get('name')))

	# 	return results

	# def getUserGroups(self, value): #now more OO
	# 	return self.getUser(value).getGroups()

	def getAllUsers(self): #now more OO
		rawResults = self.users.find({})
		results = []

		for user in rawResults:
			results.append(user)
			# results.append(self.getUser(user.get('name')))

		return results

	# def getAllUsersJSON(self): #now more OO
	# 	rawResults = self.users.find({})
	# 	results = []

	# 	for user in rawResults:
	# 		results.append(user)
	# 		# results.append(self.getUser(user.get('name')))

	# 	return results

	# def getUsersFromGroup(self, value): #now more OO
	# 	results = []

	# 	#it might be like this, but need to think how imploemet this in right way
	# 	#for user in self.users.find({'groups.name': value})

	# 	group = self.getGroup(value)
		
	# 	for user in self.getAllUsers():
	# 		if group in user.getGroups():
	# 			results.append(user)

	# 	return results

	# def getGroupCatalogs(self, value): #now more OO
	# 	return self.getGroup(value).get('catalogs')

	# def getAllCatalogs(self): #now more OO
	# 	rawResults = self.catalogs.find({})
	# 	results = []

	# 	for catalog in rawResults:
	# 		results.append(self.getCatalog(catalog.get('name')))

	# 	return results

	# def getRecordsFromCatalog(self, value): #now more OO
	# 	results = []

	# 	#it might be like this, but need to think how imploemet this in right way
	# 	#for user in self.users.find({'groups.name': value})

	# 	catalog = self.getCatalog(value)

	# 	for record in self.getAllRecords():
	# 		if catalog == record.get('catalog'):
	# 			results.append(record)

	# 	return results

	def getAllRecords(self): #now more OO
		rawResults = self.records.find({})

		results = []
		for record in rawResults:
			results.append(record)

		return results

	### Update/replace section ###

	def updateRecord(self, id, **kwargs): #need add encryption of password 
		if self.isRecordExists(id):
			result = {}
			if 'password' in kwargs:
				updatedKwargs = kwargs.copy()
				updatedKwargs['password'] = self.encryptPassword(kwargs['password'])
				result = self.records.update_one({'_id': id} , {'$set': updatedKwargs})
			else:
				result = self.records.update_one({'_id': id} , {'$set': kwargs})
			if result.modified_count != 1:
				raise Exception('can\'t update record ' + id + '.')
		else:
			raise NoSuchRecordException(id)

	# def modifyObject(self, objectType, objectRef, objectProperty, value):
	# 	if objectType == 'catalog':
	# 		if objectProperty == 'name':
	# 			#NEED TO IMPLEMENT CHECK FOR CORRECT WORK
	# 			self.records.update({'catalog.name': objectRef.get('name')}, {'$set': {'catalog.name': value}}, multi = True)
	# 			self.catalogs.update(objectRef, {'$set': {'name': value}})

	# 	elif objectType == 'group':
	# 		if objectProperty == 'name':
	# 			usersInThisGroup = self.getUsersFromGroup(objectRef.get('name'))
	# 			self.users.update({'groups': objectRef}, {'$pull': {'groups': objectRef}}, multi = True)
	# 			self.groups.update(objectRef, {'$set': {'name': value}})
	# 			newGroup = self.getGroup(value)

	# 			for element in usersInThisGroup:
	# 				user = self.getUser(element.get('_id'))
	# 				self.users.update(user, {'$push': {'groups': newGroup}})

	# 		elif objectProperty == 'catalogs':
	# 			raise Exception('lazy developer forgot to implement this method.')
				
	# 	elif objectType == 'record':
	# 		if objectProperty == ('name' or 'serverAddress' or 'username' or 'password' or 'url' or 'notes'):
	# 			self.records.update(objectRef, {'$set': {objectProperty: value}})
	# 		elif objectProperty == 'catalog':
	# 			self.records.update(objectRef, {'$set': {objectProperty: self.getCatalog(value)}})
			
	# 	elif objectType == 'user':
	# 		if objectProperty == ('name' or 'password' or 'apiToken' or 'temporalToken'):
	# 			self.users.update(objectRef, {'$set': {objectProperty: value}})
	# 		elif objectProperty == 'groups':
	# 			raise Exception('lazy developer forgot to implement this method.')

	# def addGroupAccessToCatalog(self, groupName, catalogName):
	# 	if self.__isGroupExists(groupName) == True:
	# 		if self.__isCatalogExists(catalogName) == True:
	# 			if self.__isGroupHaveAccessToCatalog(groupName, catalogName) == False:
	# 				result = self.groups.update_one({'name': groupName}, {'$push': {'catalogs': self.getCatalog(catalogName)}})

	# 				if result.modified_count != 1:
	# 					raise Exception('access to catalog "' + catalogName + '" has been NOT granted for group "' + groupName + '".')

	# 				#need to find every user with such group and update catalogs list
	# 				#need replace with __renewObjewctType
	# 				affectedUsersList = self.getUsersFromGroup(groupName)
	# 				for user in affectedUsersList:
	# 					self.removeUserFromGroup(groupName, user.get('name'))
	# 					self.addUserToGroup(groupName, user.get('name'))
	# 			else:
	# 				raise Exception('group "' + groupName + '" already have access to catalog "' + catalogName + '".')
	# 		else:
	# 			raise Exception('catalog "' + catalogName + '" does not exists.')
	# 	else:
	# 		raise Exception('group "' + groupName + '" does not exists.')

	# def removeGroupAccessToCatalog(self, groupName, catalogName): #should group have access at least to one catalog??? 
	# 	if self.__isGroupExists(groupName) == True:
	# 		if self.__isCatalogExists(catalogName) == True:
	# 			if self.__isGroupHaveAccessToCatalog(groupName, catalogName) == True:
	# 				if groupName == 'administrators' and catalogName == 'all':
	# 					raise Exception('meh... you can\'t do this, slave.')
						
	# 				else:
	# 					result = self.groups.update_one({'name': groupName}, {'$pull': {'catalogs': self.getCatalog(catalogName)}})

	# 					if result.modified_count != 1:
	# 						raise Exception('access to catalog "' + catalogName + '" has been NOT deleted for group "' + groupName + '".')

	# 					#need replace with __renewObjewctType
	# 					affectedUsersList = self.getUsersFromGroup(groupName)
	# 					for user in affectedUsersList:							
	# 						self.removeUserFromGroup(groupName, user.get('name'))
	# 						self.addUserToGroup(groupName, user.get('name'))
	# 			else:
	# 				raise Exception('group "' + groupName + '" already have NOT access to catalog "' + catalogName + '".')
	# 		else:
	# 			raise Exception('catalog "' + catalogName + '" does not exists.')
	# 	else:
	# 		raise Exception('group "' + groupName + '" does not exists.')

	# def addUserToGroup(self, groupName, username): #adds user in group
	# 	if self.isUserExists(username) == True:
	# 		if self.__isGroupExists(groupName) == True:
	# 			if self.__isUserInGroup(username, groupName) == False:
	# 				result = self.users.update_one({'name': username}, {'$push': {'groups': self.getGroup(groupName)}})
					
	# 				if result.modified_count != 1:
	# 					raise Exception('user "' + username + '" has been NOT added to group "' + groupName +'".')
	# 			else:
	# 				raise Exception('user "' + username + '" already in group "' + groupName + '".')
	# 		else:
	# 			raise Exception('group "' + groupName + '" does not exists.')
	# 	else:
	# 		raise Exception('user "' + username + '" does not exists.')

	# def removeUserFromGroup(self, groupName, username): #
	# 	if self.isUserExists(username) == True:
	# 		if self.__isGroupExists(groupName) == True:
	# 			if self.__isUserInGroup(username, groupName) == True:
	# 				if (self.__isLastGroupForUser(username) == False) or (self.__isLastGroupForUser(username) == True and inspect.stack()[1].function == ('addGroupAccessToCatalog') or (self.__isLastGroupForUser(username) == True and inspect.stack()[1].function == 'removeGroupAccessToCatalog') or (self.__isLastGroupForUser(username) == True and inspect.stack()[1].function == 'renameGroup')):
	# 					result = self.users.update_one({'name': username}, {'$pull': {'groups': {'_id': self.getGroup(groupName).get('_id')}}})

	# 					if result.modified_count != 1:
	# 						raise Exception('user "' + username + '" has been NOT removed from group "' + groupName + '".')
	# 				else:
	# 					raise Exception('group "' + groupName + '" is last for user "' + username +'".')
	# 			else:
	# 				raise Exception('user "' + username + '" already not in group "' + groupName + '".')
	# 		else:
	# 			raise Exception('group name "' + groupName + '" does not exists.')
	# 	else:
	# 		raise Exception('user "' + username + '" does not exists.')

	def changeUserPassword(self, value, oldPassword, newPassword): #need to make handler for checking user who make password change
		user = self.__oIH(value)

		if self.isUserExists(user):
			if self.makePasswordHash(oldPassword) == self.getPasswordHash(user):
				result = self.users.update_one(user, {'$set': {'password': self.makePasswordHash(newPassword)}})

				if result.modified_count != 1:
					raise Exception('password for user ' + user + ' have been not changed!')
			else:
				raise Exception('wrong current password.')
		else:
			raise NoSuchUserException(user)

	def renameUser(self, value, newName):
		user = self.__oIH(value)

		if self.isUserExists(user):
			# if username != 'admin':
				result = self.users.update_one(user, {'$set': {'name': newName}})

				if result.modified_count != 1:
					raise Exception('name for user "' + user + '" have been not changed!')
			# else:
				# raise Exception('you can\'t do this, broh.')
		else:
			raise NoSuchUserException(user)

	# def renameGroup(self, groupName, newName): 
	# 	if self.__isGroupExists(groupName) == True:
	# 		if groupName != 'administrators':
	# 			affectedUsersList = self.getUsersFromGroup(groupName)

	# 			for user in affectedUsersList:							
	# 				self.removeUserFromGroup(groupName, user.get('name'))

	# 			result = self.groups.update_one({'name': groupName}, {'$set': {'name': newName}})

	# 			if result.modified_count != 1:
	# 				for user in affectedUsersList:
	# 					self.addUserToGroup(groupName, user.get('name'))
	# 				raise Exception('name for group "' + groupName + '" have been not changed!')
	# 			elif result.modified_count == 1:
	# 				for user in affectedUsersList:
	# 					self.addUserToGroup(newName, user.get('name'))

	# 		else:
	# 			raise Exception('you can\'t do this, broh.')
	# 	else:
	# 		raise NoSuchGroupException(groupName)

	# def renameCatalog(self, catalogName, newCatalogName): 
	# 	if self.__isCatalogExists(catalogName) == True:
			
	# 		# affectedRecordsList = self.getRecordsFromCatalog(catalogName)

	# 		# for record in affectedRecordsList:							
	# 		# 	self.removeUserFromGroup(groupName, user.get('name'))

	# 		# result = self.groups.update_one({'name': groupName}, {'$set': {'name': newName}})

	# 		# if result.modified_count != 1:
	# 		# 	for user in affectedUsersList:
	# 		# 		self.addUserToGroup(groupName, user.get('name'))
	# 		# 	raise Exception('name for group "' + groupName + '" have been not changed!')
	# 		# elif result.modified_count == 1:
	# 		# 	for user in affectedUsersList:
	# 		# 		self.addUserToGroup(newName, user.get('name'))

	# 		self.modifyObject('catalog', self.getCatalog(catalogName), 'name', newCatalogName)

	# 	else:
	# 		raise NoSuchGroupException(groupName)


			
	# 	if catalogName != 'all':
	# 		if self.__isCatalogExists(catalogName):
	# 			recordsWithOdlCatalogName = self.records.find({'catalog': oldCatalogName})

	# 			pass

	# # # def changeRecordCatalog(self, recordName, oldCatalogName, newCatalogName): #BE VERY CAREFUL WITH THIOS METHOD! IT MAY WORKS NOT EXACTLY AS I WISH! 
	# # 	if self.isRecordExists(recordName, oldCatalogName):
	# # 		if self.__isCatalogExists(newCatalogName):
	# # 			record = self.getRecord(recordName, oldCatalogName)
	# # 			newCatalog = self.getCatalog(newCatalogName)

	# # 			addResult = self.records.update_one(record, {'$set': {'catalog': self.getCatalog(newCatalogName)}})
				
	# # 			if addResult.modified_count != 1:
	# # 				raise Exception('group for record "' + recordName + '" have been NOT changed!')				
	# # 		else:
	# # 			raise NoSuchCatalogException(newCatalogName)
	# # 	else:
	# # 		raise NoSuchRecordException(recordName) 

	# def removeRecordFromcatalog(self, recordName, catalogName):
	# 	pass

	# def addRecordToCatalog(self, recordName, catalogName):
	# 	pass

	### Delete section ###

	# def deleteGroup(self, groupName):
	# 	if self.__isGroupIsEmpty(groupName) == True:
	# 		if groupName != 'administrators':
	# 			result = self.groups.delete_one(self.groups.find_one({'name': groupName}))

	# 			if result.deleted_count != 1:
	# 				raise Exception('group "' + groupName + '" has been NOT deleted.')
	# 		else:
	# 			raise Exception('you can not delete \"administrators\" group.')
	# 	else:
	# 		raise Exception('group "' + groupName +'" is not empty or not exists.')

	def deleteUser(self, value):
		user = self.__oIH(value)

		if self.isUserExists(value):
			# if username != 'admin':
				result = self.users.delete_one(self.users.find_one(user))

				if result.deleted_count != 1:
					raise Exception('user "' + user + '" has been NOT deleted.')
			# else:
			# 	raise Exception('you can not remove \"admin\" user.')
		else:
			raise NoSuchUserException(user)

	# def deleteCatalog(self, catalogName):
	# 	if self.__isRecordsGroupIsEmpty(catalogName) == True:
	# 		result = self.catalogs.delete_one(self.catalogs.find_one({'name': catalogName}))

	# 		if result.deleted_count != 1:
	# 			raise Exception('catalog "' + catalogName + '" has been NOT deleted.')
	# 	else:
	# 		raise Exception('catalog "' + catalogName +'" is not empty or not exists.')

	def deleteRecord(self, value):
		record = self.__oIH(value)

		if self.isRecordExists(value):
			result = self.records.delete_one(self.records.find_one(record))

			if result.deleted_count != 1:
				raise Exception('record "' + record + '" has been NOT deleted.')
		else:
			raise NoSuchRecordException(record)

	### DB init section ###

	def initDB(self): 

		# self.createGroup('administrators')
		# self.createGroup('half-admins')
		# self.createGroup('users')
		# self.createCatalog('testCatalog')
		# self.createCatalog('anotherTestCatalog')
		# self.addGroupAccessToCatalog('users', 'testCatalog')
		# self.addGroupAccessToCatalog('half-admins', 'anotherTestCatalog')
		# self.catalogs.insert_one({'name': 'all'})
		# self.addGroupAccessToCatalog('administrators', 'all')
		self.createUser('admin', 'admin')
		self.createUser('admin4eg', 'admin4egP@ssw0rd')
		self.createUser('user', 'userPassw0rd')
				
		self.createRecord(
			'testRecord1', 
			'localhost1', 
			'testUser1', 
			'testPassword1', 
			url='https://localhost1/', 
			notes='some test notes here1')
		self.createRecord(
			'testRecord2', 
			'localhost2', 
			'testUser2', 
			'testPassword2', 
			url='https://localhost2/', 
			notes='some test notes here2')
		self.createRecord(
			'testRecord3', 
			'localhost3', 
			'testUser3', 
			'testPassword3', 
			url='https://localhost/3', 
			notes='some test notes here3')
		self.createRecord(
			'testRecord4', 
			'localhost4', 
			'testUser4', 
			'testPassword4', 
			url='https://localhost/4', 
			notes='some test notes here4')
		self.createRecord(
			'testRecord5', 
			'localhost5', 
			'testUser5', 
			'testPassword5', 
			url='https://localhost/5', 
			notes='some test notes here4')

	### Test methods ###

	def clearDB(self):
		# self.groups.remove()
		self.users.remove()
		# self.catalogs.remove()
		self.records.remove()

	### web methods ###

	# def createExpTime(self): #need to check this for right working
	# 	now = datetime.datetime.now()
	# 	hour = now.hour
	# 	day = now.day
	# 	month = now.month
	# 	year = now.year
	# 	replacedNow = ''

	# 	if hour >= 0 and hour <= 22:
	# 		replacedNow = now.replace(hour = hour + 1)
	# 	elif hour == 23:
	# 		if day >=1 and day <= 27:
	# 			replacedNow = now.replace(day = day +1, hour = 0)
	# 		elif (month == 2 and day == 28) and (((year % 4 == 0) and (year % 100 != 0)) or (year % 400 == 0)):
	# 			replacedNow = now.replace(day = day +1, hour = 0)
	# 		elif (month == 2 and day == 29) and (((year % 4 == 0) and (year % 100 != 0)) or (year % 400 == 0)):
	# 			replacedNow = now.replace(month = month + 1, day = 1, hour = 0)
	# 		elif (month == 2 and day == 28) and ((year % 4 != 0) or ((year % 100 == 0) and (year % 400 != 0))):
	# 			replacedNow = now.replace(month = month + 1, day = 1, hour = 0)
	# 		elif (day >= 28 and day <= 31) and (month == 1 or month == 3 or month == 5 or month == 7 or month == 8 or month == 10):
	# 			replacedNow = now.replace(month = month + 1, day = 1, hour = 0)
	# 		elif (day >= 28 and day <= 30) and (month == 2 or month == 4 or month == 5 or month == 9 or month == 11):
	# 			replacedNow = now.replace(month = month + 1, day = 1, hour = 0)
	# 		elif (day >= 28 and day <= 30) and (month == 12):
	# 			replacedNow = now.replace(year = year + 1, month = 1, day = 1, hour = 0)

	# 	return str(replacedNow)

	# def getExpTime(self, value):
	# 	result = self.getUser(value).get('temporalToken').get('expTime')

	# 	if result != '':
	# 		return result
	# 	else:
	# 		raise Exception('expiration time not set.')

	# def checkExpTimeIsValid(self, value):
	# 	result = False

	# 	expTime = datetime.datetime.strptime(self.getExpTime(value), '%Y-%m-%d %H-%M-%S.%f') 

	# 	if expTime >= datetime.datetime.now():
	# 		result = True
		
	# 	return result

	# def setExpTime(self, value):
	# 	pass

	# def renewExpTime(self, value):
	# 	pass

	# def createTemporalToken(self, expTime):
	# 	return {'temporalToken': PassGen.PassGen().generatePassword(32, True, True, True, False), 'expTime': expTime}

	# def setTemporalToken(self, value, token):
	# 	self.modifyObject('user', self.getUser(value), 'temporalToken', token)

	# def getTemporalToken(self, value):
	# 	return self.getUser(value).get('temporalToken')




	def createApiToken(self):
		return PassGen.PassGen().generatePassword(64, True, True, True, False)

	def getPasswordHash(self, value): 
		if self.getUser(value) != None:
			return self.getUser(value).get('password') 

	def makePasswordHash(self, passphrase):
		return MD5Crypter.MD5Crypter().getHash(passphrase)

	def validateUser(self, username, password): 
		return True if self.getPasswordHash(username) == self.makePasswordHash(password) else False;

class NoSuchGroupException(Exception):
	def __init__(self, groupName):
		Exception.__init__(self, 'group \"{}\" does not exists.'.format(groupName))

class NoSuchUserException(Exception):
	def __init__(self, username):
		Exception.__init__(self, 'user \"{}\" does not exists.'.format(username))

class NoSuchCatalogException(Exception):
	def __init__(self, catalogName):
		Exception.__init__(self, 'catalog \"{}\" does not exists.'.format(catalogName))

class NoSuchRecordException(Exception):
	def __init__(self, recordName):
		Exception.__init__(self, 'record \"{}\" does not exists.'.format(recordName))

class IllegalArgumentNumberException(Exception):
	def __init__(self, desiredArgumentCount, currentArgumentCount):
		Exception.__init__(self, 'should be {} argument(s) instead of {}.'.format(desiredArgumentCount, currentArgumentCount))

class IllegalArgumentTypeException(Exception):
	def __init__(self, argument):
		Exception.__init__(self, '{} is unsupported argument type.'.format(type(argument)))