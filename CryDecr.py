#!/usr/bin/env python

import blowfish
from os import urandom 

class CryDecr:
	
	def __generateSalt(self):
		self.key = urandom(56)

	def __saveSalt(self):

	def __loadSalt(self):

	def makeCrypt(self, phrase):

	def makeDecrypt(self, phrase):
