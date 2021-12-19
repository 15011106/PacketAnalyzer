import sqlite3
import os
"""
Data base handler module for pcap file anlyzer
To do list:

Created by YoonJong Na
Last modified: 2017-10-24

To do list
[X]. Make document	-> Maybe this is enough
[O]. Make DB
[O]. Make Table
[O]. ADD Column
[X]. Delete Table 	-> Maybe we don't need it

[O]. Insert data
[X]. Delete certain Database  -> ADD it when we need it
[O]. Get data of specific table
[O]. Get specific data of certain table
[O]. Fileter(?) maybe -> ADD it when we need it...

[O]. Make query and send
"""

class PcapDBhandler:
	def __init__(self, dbName):
	### Check and create database of dbName at position ./result/DB/dbName then create database handler
		self.dbName = ("./result/DB/" + str(dbName) + ".db")
		self._checkDB()
		self.conn = sqlite3.connect(self.dbName)
		self.cur = self.conn.cursor()

	def _checkDB(self):
		if not os.path.exists("./result/DB"):
			os.makedirs("./result/DB")
			print "Database file not found database created at...:{}".format(self.dbName)


	### Methods related to creating table
	def createTable(self, tableName, columnDict):
		ret = -1;
		table = "test"
		try:
			Query = """CREATE TABLE IF NOT EXISTS \'"""
			Query += tableName
			Query += "\'"
			Query += " ("
			for eachColumn in columnDict:
				#print eachColomn
				Query += eachColumn
				Query += " "
				Query += columnDict[eachColumn]
				Query +=", "
			Query = Query[:-2]
			Query +="); "
			self.sendQuery(Query)
			ret = 1
			#print "Successfully Created Table :{}".format(tableName)
			return ret
		except:
			print "Err making table"
			return ret


	### Add colomn with this
	def addColumn(self, table, columnDict):
		ret = -1
		table = "test"
		## Check if it is list type, Dictionary should be... {name:datatype}
		try:
			for eachColumn in columnDict:
				Query = """ALTER TABLE """
				Query += table
				Query +=" ADD COLUMN \'"
				Query += eachColumn
				Query += "\' "
				Query += columnDict[eachColumn]
				Query += ";"
				self.sendQuery(Query)
				#print "Column :{} successfully added! ".format(eachColumn)
			ret = 1
			return ret
		except:
			print "Err adding column"
			return ret


	def insertItem(self, table, itemDict):
		ret = -1
		table = "test"
		try:
			Query = """INSERT INTO \'"""
			Query += table
			Query += "\' ("
			columnQuery = ""
			valuesQuery = "values ("
			itemTuple = []

			for eachColumn in itemDict:
				#print eachColumn
				columnQuery += eachColumn
				columnQuery += ", "
				itemTuple.append(itemDict[eachColumn])
				valuesQuery += "?, "

			columnQuery = columnQuery[:-2]
			valuesQuery = valuesQuery[:-2]
			Query += columnQuery
			Query += ") "
			Query += valuesQuery
			Query += ") "

			itemTuple = tuple(itemTuple)
			#print Query, itemTuple
			self.cur.execute(Query,  itemTuple)
			self.conn.commit()
			#print "Items succsesfully added!"
			ret = 1
			return ret;
		except:
			print "Err inserting item"
			return ret;


	### Methods for getting items from table
	def getItem(self, targetTable, targetColumn, targetData):
		ret = -1
		queryAdditionalInfo = ()
		targetTable = "test"
		### Case 1: From certain column and data
		if(targetColumn and targetData):	
			Query = """SELECT """

			### Column information handler
			for eachTargetColumn in targetColumn:
				Query +=eachTargetColumn
				Query += ", "
			Query = Query[:-2]
			Query += " FROM "
			Query += targetTable

			### Data information handler
			Query += " WHERE "
			targetDataList = []
			for eachTargetData in targetData:
				Query += eachTargetData
				Query +="=? and "
				### information about target column then data
				targetDataList.append(targetData[eachTargetData])
			Query = Query[:-5]
			targetDataTuple = tuple(targetDataList)
			self.cur.execute(Query, targetDataTuple)
			ret = self.cur.fetchall()
			return ret

		### Case 2: From certaion column only
		elif (targetColumn):
			Query = """SELECT """

			### Column information handler
			for eachTargetColumn in targetColumn:
				Query +=eachTargetColumn
				Query += ", "
			Query = Query[:-2]
			Query += " FROM "
			Query += targetTable

			self.cur.execute(Query)
			ret = self.cur.fetchall()
			return ret

		### Case 3: Only certaion data
		elif (targetData):
			Query = """SELECT * FROM """
			Query += targetTable

			### Data information handler
			Query += " WHERE "
			targetDataList = []
			for eachTargetData in targetData:
				Query += eachTargetData
				Query +="=? and "
				### information about target column then data
				targetDataList.append(targetData[eachTargetData])
			Query = Query[:-5]
			#print Query
			targetDataTuple = tuple(targetDataList)
			#print targetDataTuple
			self.cur.execute(Query, targetDataTuple)

			ret = self.cur.fetchall()
			return ret

		### Case 4: GET ALL
		else:
			Query = """SELECT * FROM """
			Query += targetTable
			self.cur.execute(Query)
			ret = self.cur.fetchall()
			return ret


	### Methods that send Query
	def sendQuery(self, Query):
		self.cur.execute(Query)
		self.conn.commit()

	## Use it to closing database connection
	def closeDB(self):
		self.conn.close()





"""
Main function for test.
Example code included here


def ExampleCode():
	### Database name you wants to create
	testDB = "test.db"

	### Step1: Set database name as following
	test = PcapDBhandler(testDB)

	### Step2: Create table like next it will deal with duplicate
	TableName = "TESTTABLE"
	columnDict = {	"SIP":"TEXT",
					"DIP":"TEXT",
					"SPORT":"TEXT"	}
	test.createTable(TableName, columnDict)

	### Step2-1: Add colomn for table if you forgot something
	columnDictToAdd = { "DPORT":"TEXT" }

	test.addColumn(TableName, columnDictToAdd)

	### Step3: Make dictionary of items wants to insert into
	dataList = {	"SIP":"192.168.0.1",
					"DIP":"192.168.0.2",
				  	"SPORT":"2222",
				  	"DPORT":"2223"
				  	}
	test.insertItem(TableName, dataList)

	### Step4: Get  ALLitems from table	
	print "STEP 4!"
	ret = test.getItem(TableName, None, None)
	for eachRow in ret:
		print eachRow

	### Step5: Get items from specific column
	print "STEP 5!"
	targetColumn = ["SIP", "DIP"]
	ret = test.getItem(TableName, targetColumn, None)
	for eachRow in ret:
		print eachRow

	### Step6: Get specific data 
	targetData = {"SIP":"192.168.0.1"}
	ret = test.getItem(TableName, None, targetData)
	print "STEP 6!"
	for eachRow in ret:
		print ret

	### Step7? Get specific DATA from specific COLUMN
	ret = test.getItem(TableName, targetColumn, targetData)
	print "STEP 7!"
	for eachRow in ret:
		print ret





	test.closeDB()

if __name__ == "__main__":
	ExampleCode();
"""
## Main functions for test