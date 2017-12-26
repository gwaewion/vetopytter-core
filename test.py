#!/usr/bin/env python

import MongoDBTalker

print('MongoDBTalker')

db = MongoDBTalker.MongoDBTalker('localhost', 'vl', 'P@ssw0rd', 'vl')

def testGetGroup():
	print('\ngetGroup(users): \n' + str(db.getGroup('users')) )

def testGetAllGroups():
	print('\ngetAllGroups:')
	for item in db.getAllGroups():
		print(str(item))

def testGetUserGroups():
	print('\ngetUserGroups(admin4eg):')
	for item in db.getUserGroups('admin4eg'):
		print(str(item))

def testGetUser():
	print('\ngetUser(admin4eg):' + '\n' + str(db.getUser('admin4eg')))

def testGetAllUsers():
	print('\ngetAllUsers:')
	for item in db.getAllUsers():
		print(str(item))

def testGetUsersFromGroup():
	print('\ngetUsersFromGroup(users):')
	for item in db.getUsersFromGroup('users'):
		print(str(item))


testGetGroup()
testGetAllGroups()
testGetUserGroups()
testGetUser()
testGetAllUsers()
testGetUsersFromGroup()