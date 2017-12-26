import datetime

import yaml

import PassGen


class Entity():
	def __eq__(self, otherObject):
		result = False

		if isinstance(otherObject, self.__class__):
			if self.__dict__ == otherObject.__dict__:
				result = True

		return result


class Catalog(Entity):
	def __init__(self, id, name):
		# super(Catalog, self).__init__()
		self.__id = id
		self.__name = name

	def __repr__(self):
		return '{\'_id\': {}, \'name\': {}}'.format(self.__id, self.__name)

	def getId(self):
		return self.__id

	def getName(self):
		return self.__name

	def setName(self, name):
		self.__name = name


class Group(Entity):
	def __init__(self, id, name, catalogs):
		# super(Catalog, self).__init__()
		self.__id = id
		self.__name = name
		self.__catalogs = catalogs #list #need add check for type of inserted object

	def __str__(self):
		return '\{\'_id\': {}, \'name\': {}, \'catalogs\': {}\}'.format(self.__id, self.__name, self.__catalogs)

	def getId(self):
		return self.__id

	def getName(self):
		return self.__name

	def setName(self, name):
		self.__name = name

	def getCatalogs(self):
		return self.__catalogs

	def setCatalogs(self, catalogs):
		self.__catalogs = catalogs	


class Record(Entity):
	def __init__(self, id, name, serverAddress, username, password, catalogName, url='', notes=''):
		# super(Catalog, self).__init__()
		self.__id = id
		self.__name = name
		self.__serverAddress = serverAddress
		self.__username = username
		self.__password = password
		self.__catalogName = catalogName
		self.__url = url
		self.__notes = notes

	# def __str__(self):
	# 	return '\{\'_id\': {}, \'name\': {}, \'serverAddress\': {}, \'username\': {}, \'password\': {}, \'catalogName\': {}, \'url\': {}, \'notes\': {}\}'.format(self.id, self.name, self.serverAddress, self.username, self.password, self.catalogName, self.url, self.notes)

	def getId(self):
		return self.__id

	def getName(self):
		return self.__name

	def setName(self, name):
		self.__name = name

	def getServerAddress(self):
		return self.__serverAddress

	def setServerAddress(self, serverAddress):
		self.__serverAddress = serverAddress

	def getUsername(self):
		return self.__username

	def setUsername(self, username):
		self.__username = username

	def getPassword(self):
		return self.__password

	def setPassword(self, password):
		self.__password = password

	def getCatalogName(self):
		return self.__catalogName

	def setCatalogName(self, catalogName):
		self.__catalogName = catalogName

	def getUrl(self):
		return self.__url

	def setUrl(self, url):
		self.__url = url

	def getNotes(self):
		return self.__notes

	def setNotes(self, notes):
		self.__notes = notes


class User(Entity):
	def __init__(self, id, name, password, groups, apiToken):
		# super(Catalog, self).__init__()
		self.__id = id
		self.__name = name
		self.__password = password
		self.__groups = groups #list #need add check for type of inserted object
		self.__apiToken = apiToken

	# def __str__(self):
	# 	return '\{\'_id\': {}, \'name\': {}, \'password\': {}, \'groups\': {}, \'apiToken\': {}, \'tempToken\': {}\}'.\
	# 	format(self.id, self.name, self.password, self.groups, self.apiToken, self.tempToken)

	def getId(self):
		return self.__id

	def getName(self):
		return self.__name

	def setName(self, name):
		self.__name = name

	def getPassword(self):
		return self.__password

	def setPassword(self, password):
		self.__password = password

	def getGroups(self):
		return self.__groups

	def setGroups(self, groups):
		self.__groups = groups

	def getApiToken(self):
		return self.__apiToken

	def setApiToken(self, apiToken):
		self.__apiToken = apiToken


class Config():
	def __init__(self, filename):
		with open(filename) as file:
			config = yaml.load(file)

			self.__dbHost = config.get('db').get('host')
			self.__dbName = config.get('db').get('database')
			self.__dbUser = config.get('db').get('username')
			self.__dbPass = config.get('db').get('password')

			self.__secret = config.get('general').get('secret')

	def getDbHost(self):
		return self.__dbHost

	def getDbName(self):
		return self.__dbName

	def getDbUser(self):
		return self.__dbUser

	def getDbPass(self):
		return self.__dbPass

	def getSecret(self):
		return self.__secret


# class Session():
# 	def __init__(self):
# 		self.__key = PassGen.PassGen().generatePassword(32, True, True, True, False)
# 		self.__expTime = self.__createExpTime()

# 	def __createExpTime(self): 
# 		# now = datetime.datetime.now()
# 		# hour = now.hour
# 		# day = now.day
# 		# month = now.month
# 		# year = now.year
# 		# replacedNow = ''

# 		# if hour >= 0 and hour <= 22:
# 		# 	replacedNow = now.replace(hour = hour + 1)
# 		# elif hour == 23:
# 		# 	if day >=1 and day <= 27:
# 		# 		replacedNow = now.replace(day = day +1, hour = 0)
# 		# 	elif (month == 2 and day == 28) and (((year % 4 == 0) and (year % 100 != 0)) or (year % 400 == 0)):
# 		# 		replacedNow = now.replace(day = day +1, hour = 0)
# 		# 	elif (month == 2 and day == 29) and (((year % 4 == 0) and (year % 100 != 0)) or (year % 400 == 0)):
# 		# 		replacedNow = now.replace(month = month + 1, day = 1, hour = 0)
# 		# 	elif (month == 2 and day == 28) and ((year % 4 != 0) or ((year % 100 == 0) and (year % 400 != 0))):
# 		# 		replacedNow = now.replace(month = month + 1, day = 1, hour = 0)
# 		# 	elif (day >= 28 and day <= 31) and (month == 1 or month == 3 or month == 5 or month == 7 or month == 8 or month == 10):
# 		# 		replacedNow = now.replace(month = month + 1, day = 1, hour = 0)
# 		# 	elif (day >= 28 and day <= 30) and (month == 2 or month == 4 or month == 5 or month == 9 or month == 11):
# 		# 		replacedNow = now.replace(month = month + 1, day = 1, hour = 0)
# 		# 	elif (day >= 28 and day <= 30) and (month == 12):
# 		# 		replacedNow = now.replace(year = year + 1, month = 1, day = 1, hour = 0)

# 		return str(datetime.datetime.now() + datetime.timedelta(seconds = 3600))

# 	def getKey(self):
# 		return self.__key

# 	def _setKey(self, token):
# 		pass

# 	def getExpTime(self):
# 		return self.__expTime

# 	def _setExpTime(self, expTime):
# 		pass

# 	def renewExpTime(self):
# 		self.__expTime = self.__createExpTime()
