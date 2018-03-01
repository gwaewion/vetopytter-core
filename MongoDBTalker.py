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
#todo need make code more OO and use entity like groupObject, userObject instead use streight groupName, username etc. 
#todo make limitation for creating names for user, group, catalog or record with special characters
#todo REALLY need exception handlers
#todo add favicon
#todo add createdBy and modificatedBy for records
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

			self.groups = self.db['groups']
			self.users = self.db['users']
			self.catalogs = self.db['catalogs']
			self.records = self.db['records']
			# self.sessions = self.db['sessions']
			
			result = True
		except Exception as ex:
			print(ex)
		return result

	def closeConnection(self):
		self.talker.close()

	### Some internal cool stuff, you know ###



	### Various checks section ###

	def isObjectExists(self, objectType, objectProperty, propertyValue):
		if objectType != 'group' and objectType != 'user' and objectType != 'catalog' and objectType != 'record':
			raise IllegalArgumentException(objectType)
		elif objectProperty != 'id' and objectProperty != 'name' and objectProperty != 'oid':
			raise IllegalArgumentException(objectProperty)
		else:
			if objectProperty == 'id':
				# if objectType == 'record':
				# 	for catalog in self.catalogs.find({}):
				# 		for record in catalog.get('records'):
				# 			return True if bson.objectid.ObjectId(propertyValue) == record.get('_id') != None else False
				# else:
				check = 'self.' + objectType + 's.find_one({\'_id\': bson.objectid.ObjectId(propertyValue)})'
				return True if eval(check) != None else False
			elif objectProperty == 'name':
				# if objectType == 'record':
				# 	for catalog in self.catalogs.find({}):
				# 		for record in catalog.get('records'):
				# 			return True if propertyValue in record.get('name') != None else False
				# else:
				check = 'self.' + objectType + 's.find_one({\'name\': propertyValue})'
				return True if eval(check) != None else False
			elif objectProperty == 'oid':
				# if objectType == 'record':
				# 	for catalog in self.catalogs.find({}):
				# 		for record in catalog.get('records'):
				# 			return True if propertyValue == record != None else False
				# else:
				check = 'self.' + objectType + 's.find_one(propertyValue)'
				return True if eval(check) != None else False

	def getObject(self, objectType, objectProperty, propertyValue):
		if objectType != 'group' and objectType != 'user' and objectType != 'catalog' and objectType != 'record':
			raise IllegalArgumentException(objectType)
		elif objectProperty != 'id' and objectProperty != 'name' and objectProperty != 'oid':
			raise IllegalArgumentException(objectProperty)
		else:
			if objectProperty == 'id':
				# if objectType == 'record':
				# 	result = ''
				# 	for catalog in self.catalogs.find({}):
				# 		for record in catalog.get('records'):
				# 			if record.get('_id') == bson.objectid.ObjectId(propertyValue):
				# 				result = record
				# 	if result is not None and len(result) > 0:
				# 		return result
				# 	else:
				# 		raise NoSuchRecordException(propertyValue)
				# else:
				check = 'self.' + objectType + 's.find_one({\'_id\': bson.objectid.ObjectId(propertyValue)})'
				result = eval(check)
				if result is not None and len(result) > 0:
					return result
				else:
					raise NoSuchObjectException(objectType, objectProperty, propertyValue)
			elif objectProperty == 'name':
				# if objectType == 'record':
				# 	result = ''
				# 	for catalog in self.catalogs.find({}):
				# 		for record in catalog.get('records'):
				# 			if record.get('name') == propertyValue:
				# 				result = record
				# 	if result is not None and len(result) > 0:
				# 		return result
				# 	else:
				# 		raise NoSuchRecordException(propertyValue)
				# else:
				check = 'self.' + objectType + 's.find_one({\'name\': propertyValue})'
				result = eval(check)
				if result is not None and len(result) > 0:
					return result
				else:
					raise NoSuchObjectException(objectType, objectProperty, propertyValue)
			elif objectProperty == 'oid':
				# if objectType == 'record':
				# 	result = ''
				# 	for catalog in self.catalogs.find({}):
				# 		for record in catalog.get('records'):
				# 			if record.get('_id') == propertyValue:
				# 				result = record
				# 	if result is not None and len(result) > 0:
				# 		return result
				# 	else:
				# 		raise NoSuchRecordException(propertyValue)
				# else:
				check = 'self.' + objectType + 's.find_one(propertyValue)'
				result = eval(check)
				if result is not None and len(result) > 0:
					return result
				else:
					raise NoSuchObjectException(objectType, objectProperty, propertyValue)

	# def isCatalogExists(self, **kwargs):
	# 	if len(kwargs) != 1:
	# 		raise IllegalArgumentNumberException(1, len(kwargs))
	# 	elif not 'id' in kwargs.keys() or not 'name' in kwargs.keys():
	# 		raise IllegalArgumentTypeException(kwargs.keys())
	# 	else:
	# 		if 'id' in kwargs.keys():
	# 			for value in kwargs.values():
	# 				return True if self.catalogs.find_one({'_id': value}) != None else False
	# 		elif 'name' in kwargs.keys():
	# 			for value in kwargs.values():
	# 				return True if self.catalogs.find_one({'name': value}) != None else False

	# 	return True if self.catalogs.find_one({'_id': catalogID}) != None else False

	# def isGroupExists(self, value):
	# 	return True if self.groups.find_one(self.__oIH(value)) != None else False

	# def isRecordExists(self, value, catalogName): #now more OO
	# 	result = False

	# 	if self.__isCatalogExists(catalogName) and self.records.find_one({'$and':[self.__oIH(value), {'catalog.name': catalogName}]}) != None:
	# 		result = True

	# 	return result

	# def isRecordExists(self, value):
	# 	result = False

	# 	if self.records.find_one(self.__oIH(value)) != None:
	# 		result = True

	# 	return result

	# def isUserExists(self, value):
	# 	return True if self.users.find_one(self.__oIH(value)) != None else False

	def encryptPassword(self, plainTextPassword):
		crypter = Fernet(self.cfg.getSalt().encode())
		return bytes.decode(crypter.encrypt(str.encode(plainTextPassword)))

	def decryptPassword(self, encryptedPassword):
		crypter = Fernet(self.cfg.getSalt().encode())
		return bytes.decode(crypter.decrypt(str.encode(encryptedPassword)))

	def isUserInGroup(self, groupOid, userOid):
		return True if self.users.find({'_id': userOid, 'groups': groupOid}).count() == 1 else False

	def isGroupIsEmpty(self, groupOid):
		return True if self.isObjectExists('group', 'oid', groupOid) and self.users.find({'groups': groupOid}).count() == 0 else False

	def isLastGroupForUser(self, userOid):
		return True if len(self.users.find_one({'_id': userOid}).get('groups')) == 1 else False

	def isCatalogIsEmpty(self, catalogOid):
		return True if self.isObjectExists('catalog', 'oid', catalogOid) and len(self.catalogs.find_one({'_id': catalogOid}).get('records')) == 0 else False

	# def __isGroupHaveAccessToCatalog(self, groupName, catalogName):
	# 	result = False

	# 	if self.__isGroupExists(groupName) and self.__isCatalogExists(catalogName):
	# 		catalogs = self.getGroupCatalogs(groupName)

	# 		for catalog in catalogs:
	# 			if catalog.get('name') == catalogName:
	# 				result = True

	# 	return result	

	### Create section ###  ??? should i add return value to this functions ???

	def createGroup(self, groupName):
		if not self.isObjectExists('group', 'name', groupName):
			self.groups.insert_one({'name': groupName})
		else:
			raise GroupExistsException(groupName)

	def createUser(self, username, password, description, email, groupName):
		if self.isObjectExists('group', 'name', groupName):
			if not self.isObjectExists('user', 'name', username):
					result = self.users.insert_one({
						'name': username, 
						'password': self.makePasswordHash(password), 
						'description': description, 
						'email': email, 
						'groups': [], 
						'apiToken': self.createApiToken()})
					self.addUserToGroup(self.getObject('group', 'name', groupName).get('_id'), result.inserted_id)
			else:
				raise Exception('can\'t create user. User "' + username + '" already exists.')
		else:
			raise NoSuchGroupException(groupName)

	def createCatalog(self, catalogName, parentCatalog):
		if not self.isObjectExists('catalog', 'name', catalogName):
			self.catalogs.insert_one({'name': catalogName, 'catalogs': [], 'records': [], 'groups': []})
			self.catalogs.update_one({'name': parentCatalog}, {'$push': {'catalogs': self.catalogs.find_one({'name': catalogName}).get('_id')}})
		else:
			raise Exception('can\'t create catalog. Catalog "' + catalogName + '" already exists.')

	def createRecord(self, catalogName, recordName, serverAddress, username, password, url='', notes=''):
		if self.isObjectExists('catalog', 'name', catalogName):
			# if not self.isObjectExists('record', 'name', recordName):
				result = self.records.insert_one({
					'name': recordName, 
					'serverAddress': serverAddress, 
					'username': username, 
					'password': self.encryptPassword(password), 
					'url': url, 
					'notes': notes, 
					'creationDate': datetime.datetime.utcnow(), 
					'modificationDate': datetime.datetime.utcnow()
					})
				self.addRecordToCatalog(self.getObject('catalog', 'name', catalogName).get('_id'), result.inserted_id)
			# else:
			# 	raise Exception('can\'t create record. Record "' + recordName + '" already exists in this catalog.')	
		else:
			raise NoSuchCatalogException(catalogName)

	### Read section ###

	# def getCatalog(self, catalogID):
	# 	if self.isCatalogExists(catalogID):
	# 		return self.catalogs.find_one({'_id': catalogID})
	# 	else:
	# 		raise NoSuchCatalogException(catalogID)
		# result = self.catalogs.find_one(self.__oIH(value))
		# return self._verifyResult('catalog', result, value)

	# def getGroup(self, value): 
	# 	result = self.groups.find_one(self.__oIH(value))
	# 	return self._verifyResult('group', result, value)

	# def getRecord(self, recordID):
	# 	for catalog in self.getAllCatalogs():
	# 		if not len(catalog.get('records')) == 0:
	# 			for record in self.getRecordsFromCatalog(catalog):
	# 				pass

		# result = self.catalogs.find_one(self.__oIH(value))
		# tempResult = result.copy()
		# tempResult['password'] = self.decryptPassword(result.get('password'))
		# return self._verifyResult('record', tempResult, value)

	# def getUser(self, value):
	# 	result = self.users.find_one(self.__oIH(value))
	# 	return self._verifyResult('user', result, value)

	def getAllGroups(self):
		allGroups = self.groups.find({})
		results = []
		for group in allGroups:
			results.append(group)
		return results

	def getUserGroups(self, userOid):
		groupsOidList = self.getObject('user', 'oid', userOid).get('groups')
		result = []
		for id in groupsOidList:
			result.append(self.getObject('group', 'id', id))
		return result

	def getAllUsers(self):
		allUsers = self.users.find({})
		result = []
		for user in allUsers:
			result.append(user)
		return result

	# def getAllUsersJSON(self): #now more OO
	# 	rawResults = self.users.find({})
	# 	results = []

	# 	for user in rawResults:
	# 		results.append(user)
	# 		# results.append(self.getUser(user.get('name')))

	# 	return results

	def getGroupUsers(self, groupOid):
		results = []
		for user in self.users.find({'groups': groupOid}):
			results.append(user)
		return results

	# def getGroupCatalogs(self, value): #now more OO
	# 	return self.getGroup(value).get('catalogs')

	def getAllCatalogs(self):
		rawResults = self.catalogs.find({})
		results = []
		for catalog in rawResults:
			results.append(catalog)
		return results

	def getRecordsFromCatalog(self, catalogOid):
		recordsOids = self.getObject('catalog', 'oid', catalogOid).get('records')
		result = []
		for recordOid in recordsOids:
			result.append(self.getObject('record', 'oid', recordOid))
		return result

	def getRecordCatalog(self, recordOid):
		return self.catalogs.find_one({'records': recordOid})

	def getAllRecords(self):
		rawResults = self.records.find({})
		results = []
		for record in rawResults:
			results.append(record)
		return results

	### Update/replace section ###

	def updateRecord(self, recordOid, **kwargs):
		if self.isObjectExists('record', 'oid', recordOid):
			result = {}
			if 'password' in kwargs:
				pass
				updatedKwargs = kwargs.copy()
				updatedKwargs['password'] = self.encryptPassword(kwargs['password'])
				result = self.records.update_one({'_id': recordOid}, {'$set': updatedKwargs})
			else:
				result = self.records.update_one({'_id': recordOid}, {'$set': kwargs})
			if result.modified_count != 1:
				raise Exception('can\'t update record ' + recordOid + '.')
		else:
			raise NoSuchObjectException('record', 'oid', recordOid)

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

	def addUserToGroup(self, groupOid, userOid):
		if self.isObjectExists('group', 'oid', groupOid):
			if self.isObjectExists('user', 'oid', userOid):
				if not self.isUserInGroup(groupOid, userOid):
					result = self.users.update_one({'_id': userOid}, {'$push': {'groups': groupOid}})
					
					if result.modified_count != 1:
						raise Exception('user "' + username + '" has been NOT added to group "' + groupName +'".')
				else:
					raise Exception('user "' + username + '" already in group "' + groupName + '".')
			else:
				raise NoSuchObjectException('user', 'oid', userOid)
		else:
			raise NoSuchObjectException('group', 'oid', groupOid)

	def removeUserFromGroup(self, groupName, username):
		if self.isObjectExists('user', 'name', username):
			if self.isObjectExists('group', 'name', groupName):
				if self.isUserInGroup(groupName, username):
					if (self.isLastGroupForUser(username) == False): #or (self.isLastGroupForUser(username) == True and inspect.stack()[1].function == ('addGroupAccessToCatalog') or (self.__isLastGroupForUser(username) == True and inspect.stack()[1].function == 'removeGroupAccessToCatalog') or (self.__isLastGroupForUser(username) == True and inspect.stack()[1].function == 'renameGroup')):
						result = self.users.update_one({'name': username}, {'$pull': {'groups': self.getGroup(groupName).get('_id')}})

						if result.modified_count != 1:
							raise Exception('user "' + username + '" has been NOT removed from group "' + groupName + '".')
					else:
						raise Exception('group "' + groupName + '" is last for user "' + username +'".')
				else:
					raise Exception('user "' + username + '" already not in group "' + groupName + '".')
			else:
				raise NoSuchGroupException(groupName)
		else:
			raise NoSuchUserException(username)

	def changeUserPassword(self, username, oldPassword, newPassword): #need to make handler for checking user who make password change
		if self.isUserExists(username):
			if self.makePasswordHash(oldPassword) == self.getPasswordHash(username):
				result = self.users.update_one({'name': username}, {'$set': {'password': self.makePasswordHash(newPassword)}})
				if result.modified_count != 1:
					raise Exception('password for user ' + username + ' have been not changed!')
			else:
				raise Exception('wrong current password.')
		else:
			raise NoSuchUserException(username)

	def renameUser(self, username, newName):
		if self.isUserExists(username):
			if username != 'admin':
				result = self.users.update_one({'name': username}, {'$set': {'name': newName}})
				if result.modified_count != 1:
					raise Exception('name for user "' + username + '" have been not changed!')
			else:
				raise Exception('you can\'t do this, broh.')
		else:
			raise NoSuchUserException(username)

	def renameGroup(self, groupName, newName): 
		if self.isGroupExists(groupName):
			if groupName != 'administrators':
				result = self.groups.update_one({'name': groupName}, {'$set': {'name': newName}})
				if result.modified_count != 1:
					raise Exception('name for group "' + groupName + '" have been not changed!')
			else:
				raise Exception('you can\'t do this, broh.')
		else:
			raise NoSuchGroupException(groupName)

	def renameCatalog(self, catalogName, newName): 
		if self.isCatalogExists(catalogName):
			if catalogName != 'rootCatalog':
				result = self.catalogs.update_one({'name': catalogName}, {'$set': {'name': newName}})
				if result.modified_count != 1:
					raise Exception('name for catalog "' + catalogName + '" have been not changed!')
			else:
				raise Exception('you can\'t do this, broh.')
		else:
			raise NoSuchCatalogException(catalogName)

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

	def addRecordToCatalog(self, catalogOid, recordOid):
		if self.isObjectExists('catalog', 'oid', catalogOid):
			if self.isObjectExists('record', 'oid', recordOid):
				result = self.catalogs.update_one({'_id': catalogOid}, {'$push': {'records': recordOid}})

				if result.modified_count != 1:
					raise Exception('record "' + recordOid + '" has been NOT added to catalog "' + catalogOid + '".')
			else:
				NoSuchObjectException('record', 'oid', recordOid)
		else:
			raise NoSuchObjectException('catalog', 'oid', catalogOid)
	### Delete section ###


	def deleteGroup(self, groupName):
		if self.isGroupIsEmpty(groupName):
			if groupName != 'administrators':
				result = self.groups.delete_one(self.groups.find_one({'name': groupName}))
				if result.deleted_count != 1:
					raise Exception('group "' + groupName + '" has been NOT deleted.')
			else:
				raise Exception('you can not delete \"administrators\" group.')
		else:
			raise Exception('group "' + groupName + '" is not empty or not exists.')

	def deleteUser(self, username):
		if self.isUserExists(username):
			if username != 'admin':
				result = self.users.delete_one(self.users.find_one({'name': username}))
				if result.deleted_count != 1:
					raise Exception('user "' + username + '" has been NOT deleted.')
			else:
				raise Exception('you can not remove \"admin\" user.')
		else:
			raise NoSuchUserException(username)

	def deleteCatalog(self, catalogName):
		if self.isCatalogIsEmpty(catalogName):
			result = self.catalogs.delete_one(self.catalogs.find_one({'name': catalogName}))
			if result.deleted_count != 1:
				raise Exception('catalog "' + catalogName + '" has been NOT deleted.')
		else:
			raise Exception('catalog "' + catalogName +'" is not empty or not exists.')

	def deleteRecord(self, recordOid):
		if self.isObjectExists('record', 'oid', recordOid):
			result = self.records.delete_one({'_id': recordOid})
			self.catalogs.update_one(self.getRecordCatalog(recordOid), {'$pull': {'records': recordOid}})
			if result.deleted_count != 1:
				raise Exception('record "' + record + '" has been NOT deleted.')
		else:
			raise NoSuchObjectException('record', 'oid', recordOid)

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
		self.createGroup('admins')
		self.createGroup('users')

		self.createUser('admin', 'admin', 'very main admin', 'root@localhost', 'admins')
		self.createUser('user', 'user', 'very regular user', 'user@localhost', 'users')

		self.catalogs.insert_one({'name': 'rootCatalog', 'catalogs': [], 'records': [], 'groups': []})
		self.createCatalog('testRecords', 'rootCatalog')
		self.createCatalog('moreTestRecords', 'rootCatalog')
				
		self.createRecord(
			'testRecords',
			'testRecord1', 
			'localhost1', 
			'testUser1', 
			'testPassword1', 
			url='https://localhost1/', 
			notes='some test notes here1')
		self.createRecord(
			'testRecords',
			'testRecord2', 
			'localhost2', 
			'testUser2', 
			'testPassword2', 
			url='https://localhost2/', 
			notes='some test notes here2')
		self.createRecord(
			'testRecords',
			'testRecord3', 
			'localhost3', 
			'testUser3', 
			'testPassword3', 
			url='https://localhost/3', 
			notes='some test notes here3')
		self.createRecord(
			'testRecords',
			'testRecord4', 
			'localhost4', 
			'testUser4', 
			'testPassword4', 
			url='https://localhost/4', 
			notes='some test notes here4')
		self.createRecord(
			'testRecords',
			'testRecord5', 
			'localhost5', 
			'testUser5', 
			'testPassword5', 
			url='https://localhost/5', 
			notes='some test notes here4')

		self.createRecord(
			'moreTestRecords',
			'testRecord1', 
			'localhost1', 
			'testUser1', 
			'testPassword1', 
			url='https://localhost1/', 
			notes='some test notes here1')
		self.createRecord(
			'moreTestRecords',
			'testRecord2', 
			'localhost2', 
			'testUser2', 
			'testPassword2', 
			url='https://localhost2/', 
			notes='some test notes here2')
		self.createRecord(
			'moreTestRecords',
			'testRecord3', 
			'localhost3', 
			'testUser3', 
			'testPassword3', 
			url='https://localhost/3', 
			notes='some test notes here3')
		self.createRecord(
			'moreTestRecords',
			'testRecord4', 
			'localhost4', 
			'testUser4', 
			'testPassword4', 
			url='https://localhost/4', 
			notes='some test notes here4')
		self.createRecord(
			'moreTestRecords',
			'testRecord5', 
			'localhost5', 
			'testUser5', 
			'testPassword5', 
			url='https://localhost/5', 
			notes='some test notes here4')

	### Test methods ###

	def clearDB(self):
		self.groups.remove()
		self.users.remove()
		self.catalogs.remove()
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


	def importFromKeePass(self, dictionary):
		parentCatalog = 'rootCatalog'
		self.createCatalog(dictionary.get('name'), parentCatalog)
		if len(dictionary.get('entries')) != 0:
			for entry in dictionary.get('entries'):
				self.createRecord(dictionary.get('name'), entry.get('name'), '', entry.get('username'), entry.get('password'), entry.get('url'), entry.get('notes'))
		if len(dictionary.get('groups')) != 0:
			print(dictionary.get('groups'))
			parentCatalog = dictionary.get('name')
			print(parentCatalog)
			for nestedGroup in dictionary.get('groups'):
				self.importFromKeePass(nestedGroup)

	def createApiToken(self):
		return PassGen.PassGen().generatePassword(64, True, True, True, False)

	def getPasswordHash(self, username): 
		if self.isObjectExists('user', 'name', username):
			return self.getObject('user', 'name', username).get('password')
		else:
			raise NoSuchObjectException('user', 'name', username) 

	def makePasswordHash(self, passphrase):
		return MD5Crypter.MD5Crypter().getHash(passphrase)

	def validateUser(self, username, password): 
		return True if self.getPasswordHash(username) == self.makePasswordHash(password) else False

class NoSuchGroupException(Exception):
	def __init__(self, groupName):
		Exception.__init__(self, 'group \"{}\" does not exists.'.format(groupName))

class GroupExistsException(Exception):
	def __init__(self, groupName):
		Exception.__init__(self, 'group \"{}\" already exists.'.format(groupName))

class NoSuchUserException(Exception):
	def __init__(self, username):
		Exception.__init__(self, 'user \"{}\" does not exists.'.format(username))

class UserExistsException(Exception):
	def __init__(self, username):
		Exception.__init__(self, 'user \"{}\" already exists.'.format(username))

class NoSuchCatalogException(Exception):
	def __init__(self, catalogName):
		Exception.__init__(self, 'catalog \"{}\" does not exists.'.format(catalogName))

class NoSuchObjectException(Exception):
	def __init__(self, objectType, objectProperty, propertyValue):
		Exception.__init__(self, 'object with type \"{}\" and property \"{}\" and property value \"{}\" does not exists.'.format(objectType, objectProperty, propertyValue))

class NoSuchRecordException(Exception):
	def __init__(self, recordName):
		Exception.__init__(self, 'record \"{}\" does not exists.'.format(recordName))

class IllegalArgumentNumberException(Exception):
	def __init__(self, desiredArgumentCount, currentArgumentCount):
		Exception.__init__(self, 'should be {} argument(s) instead of {}.'.format(desiredArgumentCount, currentArgumentCount))

class IllegalArgumentTypeException(Exception):
	def __init__(self, argument):
		Exception.__init__(self, '{} is unsupported argument type.'.format(type(argument)))

class IllegalArgumentException(Exception):
	def __init__(self, argument):
		Exception.__init__(self, '\'{}\' is unsupported argument.'.format(argument))