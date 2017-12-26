#!/usr/bin/env python

# TODO: add variant with SPASE characters

from random import choice
import string

class PassGen:
	__LOWER_LETTERS = string.ascii_lowercase
	__UPPER_LETTERS = string.ascii_uppercase
	__DIGITS = string.digits
	__SPECIAL_CHARACTERS = string.punctuation

	def generatePassword(self, length, useLowerLetters = True, useUpperLetters = False, useDigits = False, useSpecialCharacters = False):
		result = ""

		variants = {'useLowerLetters': PassGen.__LOWER_LETTERS, 'useUpperLetters': PassGen.__UPPER_LETTERS, 'useDigits': PassGen.__DIGITS, 'useSpecialCharacters': PassGen.__SPECIAL_CHARACTERS}

		trues = []
		localVariables = locals().copy()

		for key in localVariables:
			if localVariables.get(key) == True:
				trues.append(key)

		choiceList = []
		for item in trues:
			for variant in variants:
				if item == variant:
					choiceList.append(variants.get(variant))
		
		for symbol in range(0, length):
			result += choice(choice(choiceList))

		return result
