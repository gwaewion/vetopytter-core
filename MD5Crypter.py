#!/usr/bin/env python

import hashlib

class MD5Crypter:
	def getHash(self, phrase):
		hasher = hashlib.md5()
		hasher.update(phrase.encode())
		return hasher.hexdigest()