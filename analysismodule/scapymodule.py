from scapy.all import *
from urllib2 import urlopen
import os
import pcapSqlite
import hashlib
import time
import urllib
import urllib2
import json

"""

Created by Kwon min Hyeok, YoonJong Na
Last modified: 2017-10-24

"""

### MD5 lib
def md5_for_file(filePath, block_size=2**20):
	md5 = hashlib.md5()
	with open( filePath , "rb" ) as f:
		while True:
			buf = f.read(block_size)
			if not buf:
				break
			md5.update( buf )
	return md5.hexdigest()


### Main analysis class
class pcapAnalysis():
	def __init__(self, pcap_path, caseName, DoISP):

		### Initial setups ###
		self.case_name = caseName
		self.pcap_path = pcap_path
		self.pcap_name = os.path.split(self.pcap_path)
		self.pcap_md5 = md5_for_file(self.pcap_path)
		

		### Pcap file exception handler ###
		if(os.path.splitext(self.pcap_path)[-1] != ".pcap"):
			print("Invalid pcap file!")
			return -1

		### Set up container for data ###

		### Or not, let's just use database file ###
		self.DBprocess(DoISP)

	### Save to database
	def DBprocess(self, DoISP):
		print DoISP
		### Make DB file ###
		self.dbname = self.case_name
		self.pcapDB = pcapSqlite.PcapDBhandler(self.dbname)


		### Set md5 of pcap file as case ###
		#tableName = self.pcap_md5
		tableName = "test"
		columnDict = {	
						"SIP":"TEXT",
						"DIP":"TEXt", 

						"SPORT":"TEXT",
						"DPORT":"TEXT",

						"SMAC":"TEXT",
						"DMAC":"TEXT",

						"TIMESTAMP":"TEXT",
						"PROTOCOL":"TEXT",
						"TCP":"TEXT",

						"SIPISP":"TEXT",
						"SIPCOUNTRY":"TEXT",
						"SIPLOC":"TEXT",

						"DIPISP":"TEXT",
						"DIPCOUNTRY":"TEXT",
						"DIPLOC":"TEXT"
						}
		self.pcapDB.createTable(tableName, columnDict)
		

		### Use IP list to avoid duplication
		ipList = []
		### DATAPROCESS ###
		print self.pcap_path
		with PcapReader(self.pcap_path) as pcap_reader:
			for eachPacket in pcap_reader:
				#print eachPacket.proto
				datalist = {						
						"SIP":"",
						"DIP":"", 

						"SPORT":"",
						"DPORT":"",

						"SMAC":"",
						"DMAC":"",

						"TIMESTAMP":"",
						"PROTOCOL":"",
						"TCP":"",

						"SIPISP":"",
						"SIPCOUNTRY":"",
						"SIPLOC":"",

						"DIPISP":"",
						"DIPCOUNTRY":"",
						"DIPLOC":""
						}
				### IP Process ###
				if(eachPacket.haslayer(IP) == 1):
					(datalist["SIP"], datalist["DIP"]) = self.ipAnalysis(eachPacket)
				### Port process ###
				if(eachPacket.haslayer(IP)):
					(datalist["SPORT"], datalist["DPORT"]) = self.portAnalysis(eachPacket)
				### MAC Process ###
				if (eachPacket.getlayer(Ether)):
					(datalist["SMAC"], datalist["DMAC"]) = self.macAnalysis(eachPacket)

				### Timestamp process ###
				if(eachPacket.time):
					datalist["TIMESTAMP"] = self.timeAnalysis(eachPacket)

				### Protocol process ###
				if(eachPacket.haslayer(IP)):
					datalist["PROTOCOL"] = self.protocolAnalysis(eachPacket)

				### TCP data process ###

				### ISP and Country process, make program slow down ###
				if(DoISP):
					if(datalist["SIP"] and datalist["SIP"][:3] != "192"):
						if datalist["SIP"] in ipList:
							targetColumn = ["SIP", "SIPISP", "SIPCOUNTRY", "SIPLOC"]
							targetData = {"SIP":datalist["SIP"]}
							ret = self.pcapDB.getItem(tableName, targetColumn, targetData)
							datalist["SIPISP"] = ret['SIPISP']
							datalist["SIPCOUNTRY"] = ret["SIPCOUNTRY"]
							datalist["SIPLOC"] = ret["SIPLOC"]
						else:
							(datalist["SIPISP"], 
								datalist["SIPCOUNTRY"],	
								datalist["SIPLOC"]) = self.getCountryISP(datalist["SIP"])
					if(datalist["DIP"] and datalist["DIP"][:3] != "192"):
						if datalist["DIP"] in ipList:
							targetColumn = ["DIP", "DIPISP", "DIPCOUNTRY", "DIPLOC"]
							targetData = {"DIP":datalist["DIP"]}
							ret = self.pcapDB.getItem(tableName, targetColumn, targetData)
							datalist["DIPISP"] = ret['DIPISP']
							datalist["DIPCOUNTRY"] = ret["DIPCOUNTRY"]
							datalist["DIPLOC"] = ret["DIPLOC"]
						else:
							(datalist["DIPISP"], 
								datalist["DIPCOUNTRY"],	
								datalist["DIPLOC"]) = self.getCountryISP(datalist["DIP"])
				### Insert processed data into database ###
				self.pcapDB.insertItem(tableName, datalist)
				#print "Done inserting"
		
		### Close database after use ###
		self.pcapDB.closeDB()




	### IP Part ###
	def ipAnalysis(self, packet):
		ret = 0
		if (packet.haslayer(IP) == 1):
			### Source IP
			ret1 = str(packet[IP].fields['src'])
			### Destination IP	
			ret2 = str(packet[IP].fields['dst'])
			return ret1, ret2

		return ret

	### Get port from packet data ###
	def portAnalysis(self, packet):
		ret1=""
		ret2=""

		if packet.haslayer(UDP) or packet.haslayer(TCP):
			ret1 = packet.sport
			ret2 = packet.dport

		return ret1, ret2
	### Get mac addr from packet ###
	def macAnalysis(self, packet):
		ret = 0
		if(packet.getlayer(Ether)):
			ret1 = packet.getlayer(Ether).src
			ret2 = packet.getlayer(Ether).dst
			return ret1, ret2

		return ret

	### Get timestamp from packet ###
	def timeAnalysis(self, packet):
		ret = 0
		#cur_time = time.ctime
		if(packet.time):
			return packet.time

		return ret

	### Get Protocol from packet ###
	def protocolAnalysis(self, packet):
		ret = 0
		ret = packet[IP].proto
		if(ret == 1):
			ret = "ICMP"
		elif(ret == 6):
			ret = "TCP"
		elif(ret == 17):
			ret = "UDP"
		return ret;

	### Get ISP and country info
	def getCountryISP(self, IP):
		try:
			datafrom = 'http://ipinfo.io/{}/json'.format(IP)
			response = urllib2.urlopen(datafrom)
			data = json.load(response)

			isp = data['org']
			country=data['country']
			loc = data['loc']

			return isp, country, loc
		except:
			return 0, 0, 0
