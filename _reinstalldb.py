#!/usr/bin/env python

import MongoDBTalker

db = MongoDBTalker.MongoDBTalker('localhost', 'vl', 'vl_password', 'vl')
db.clearDB()
db.initDB()

