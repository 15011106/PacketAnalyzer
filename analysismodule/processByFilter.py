import time
import numpy as numpy
from matplotlib import pyplot as plt
from matplotlib import dates
import datetime
import dateutil
import matplotlib.dates as md
import pcapSqlite
import os
#from analysismodule import *
from analysismodule import pcapSqlite, detect_arpPoisoning

criteria_hour = 60*60
criteria_minute = 60
"""
filterOpion = {
	"do_isp":None,
	"start_time":None,
	"end_time":None,
	"UDP":None,
	"TCP":None,
	"ICMP":None,
	"others":None,
	"SIP":None,
	"DIP":None,
	"SPORT":None,
	"DPORT":None,
	"SMAC":None,
	"DMAC":None
}
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
"""

class processByFilter():
	def __init__(self, casename, filterOption):
		self.casename = casename
		#print filterOption
		dbHandler = pcapSqlite.PcapDBhandler(self.casename)
		TableName = "*"
		targetColumn = ["TIMESTAMP", "PROTOCOL", "SIP", "DIP", "SPORT", "DPORT", "SMAC", "DMAC",
						"SIPLOC", "DIPLOC", "SIPISP", "DIPISP", "SIPCOUNTRY", "DIPCOUNTRY" ]
		targetData = {}

		### Parse filtering options ###
		if(filterOption["SIP"]):
			if(filterOption['SIP'][0] == '+'):
				targetData['SIP'] = filterOption['SIP'][1:]
			elif(filterOption['SIP'][0] == '-'):
				targetData['SIP'] = "not like ", str(filterOption['SIP'][1:])

		if(filterOption["DIP"]):
			if(filterOption['DIP'][0] == '+'):
				targetData['DIP'] = filterOption['DIP'][1:]
			elif(filterOption['DIP'][0] == '-'):
				targetData['DIP'] = "not like ", str(filterOption['DIP'][1:])

		### PORT ###
		if(filterOption['SPORT']):
			if(filterOption['SPORT'][0] == '+'):
				targetData['SPORT'] = filterOption['SPORT'][1:]
			elif(filterOption['SPORT'][0] == '-'):
				targetData['SPORT'] = "not like ", str(filterOption['SPORT'][1:])

		if(filterOption['DPORT']):
			if(filterOption['DPORT'][0] == '+'):
				targetData['DPORT'] = filterOption['DPORT'][1:]
			elif(filterOption['DPORT'][0] == '-'):
				targetData['DPORT'] = "not like ", str(filterOption['DPORT'][1:])


		### PROTOCOL
		if(filterOption['UDP']):
			targetData['PROTOCOL'] = str('UDP')

		if(filterOption['TCP']):
			if('PROTOCOL' in targetData):
				targetData['PROTOCOL'] = str(targetData['PROTOCOL']) +" AND " + str('TCP')
			else:
				targetData['PROTOCOL'] = str('TCP')

		if(filterOption['ICMP']):
			if('PROTOCOL' in targetData):
				targetData['PROTOCOL'] = str(targetData['PROTOCOL']) +" AND " + str('ICMP')
			else:
				targetData['PROTOCOL'] = str('ICMP')

		if(filterOption['others']):
			if('PROTOCOL' in targetData):
				targetData['PROTOCOL'] = str(targetData['PROTOCOL']) +" AND " + "not like UDP OR not like TCP"
			else:
				targetData['PROTOCOL'] = "not like UDP OR not like TCP"

		### Get Data from DB with filter ###
		dbHandler = pcapSqlite.PcapDBhandler(casename)
		ret = dbHandler.getItem(TableName, targetColumn, targetData)
		self.packets = ret;
		#print ret


		self.times_x = []
		self.times_y = []
		self.times_start = float(ret[0][0])
		self.times_end = float(ret[-1][0])
		self.protocol_x = []
		self.protocol_y = []
		self.IPs = []
		self.Ports = []

		self.packet_number = len(ret)
		if(filterOption['do_isp']):
			self.Loc = []
			self.country = []
			self.ISP = []
		#self.protocol_start = str(ret[0][1])
		#self.protocol_end = str(ret[0][1])

		for each_ret in ret:

			time_tmp = long(float(each_ret[0])/1) 
			protocol_tmp = each_ret[1]

			## Location data for map
			if(filterOption['do_isp']):
				if(each_ret[8] and not(each_ret[8] in self.Loc)):
					if(each_ret[8] != "0"):
						self.Loc.append(each_ret[8])
				if(each_ret[9] and not(each_ret[9] in self.Loc)):
					if(each_ret[9] != "0"):
						self.Loc.append(each_ret[9])

				if(each_ret[10] and not(each_ret[10] in self.ISP)):
					self.ISP.append(each_ret[10])
				if(each_ret[11] and not(each_ret[11] in self.ISP)):
					self.ISP.append(each_ret[11])

				if(each_ret[12] and not(each_ret[12] in self.country)):
					self.country.append(each_ret[12])
				if(each_ret[13] and not(each_ret[13] in self.country)):
					self.country.append(each_ret[13])

			## Port, IP or else
			if(not (each_ret[2] in self.IPs)):
				self.IPs.append(each_ret[2])
			if(not (each_ret[3] in self.IPs)):
				self.IPs.append(each_ret[3])

			if(not (each_ret[4] in self.Ports)):
				self.Ports.append(each_ret[4])
			if(not(each_ret[5] in self.Ports)):
				self.Ports.append(each_ret[5])

			## Time Stamp info ##
			if time_tmp in self.times_x:
				idx = self.times_x.index(time_tmp)
				#print idx
				self.times_y[idx] += 1
				
			else:
				self.times_x.append(time_tmp)
				self.times_y.append(1)

			## Protocol info ##
			if protocol_tmp in self.protocol_x:
				idx = self.protocol_x.index(protocol_tmp)
				self.protocol_y[idx] += 1
			else:
				self.protocol_x.append(protocol_tmp)
				self.protocol_y.append(1)

		self.arp = detect_arpPoisoning.detectarpPoisoning(self.packets)
		
		self.draw_protocolmap()
		self.draw_timestamp()



		#### Return Function ###
	def getProcessedData(self, filterOption):
		ret= {}
		if(filterOption['do_isp']):
			ret['loc'] = self.Loc
			ret['country_number'] = len(self.country)
			ret['ISPnumber'] = len(self.ISP)
		ret['ip_number'] = len(self.IPs)
		ret['port_number'] = len(self.Ports)
		ret['protocol_number'] = len(self.protocol_x)
		ret['packet_number'] = self.packet_number
		ret['packets'] = self.packets
		ret['arp'] = self.arp

		return ret;

	def draw_timestamp(self):
		file_path ="./result/" + str(self.casename)
		if( not os.path.exists(file_path)):
			os.makedirs(file_path)
		file_path += "/timestamp.png"

		max_y = max(self.times_y)
		maxindex = self.times_y.index(max_y)
		lengthOfAxis = len(self.times_x)
		xPos = (maxindex/lengthOfAxis)

		if xPos < 0.2:
			xPos += 0.1
		elif xPos > 0.8:
			xPos-=0.1
		else:
			xPos +=0.1

		tmp = time.ctime(self.times_start)
		tmp = dateutil.parser.parse(tmp)
		tmp = datetime.datetime.strptime(str(tmp),'%Y-%m-%d %H:%M:%S')
		x_start = datetime.datetime.strptime(str(tmp),'%Y-%m-%d %H:%M:%S')

		tmp = time.ctime(self.times_end)
		tmp = dateutil.parser.parse(tmp)
		tmp = datetime.datetime.strptime(str(tmp),'%Y-%m-%d %H:%M:%S')
		x_end = datetime.datetime.strptime(str(tmp),'%Y-%m-%d %H:%M:%S')

		for each_x in self.times_x:
			tmp = time.ctime(each_x)
			tmp = dateutil.parser.parse(tmp)
			tmp = datetime.datetime.strptime(str(tmp),'%Y-%m-%d %H:%M:%S')
			self.times_x[self.times_x.index(each_x)] = tmp

		plt.title("Packets Timestamp")
		plt.xlim([x_start,x_end])
		plt.ylim([0,max_y + max_y*2/3])
		plt.plot(self.times_x,self.times_y,'-',label="pakets",color="r",marker='o')
		plt.ylabel('Number of packets')
		plt.xlabel('date')
		plt.annotate('MAX packets', xy = (self.times_x[maxindex],max_y), xytext = (xPos, 0.6), textcoords = ('axes fraction'), fontsize = 14 ,arrowprops=dict(arrowstyle="->",alpha=1))

		plt.grid(True)
		plt.legend(loc=2)
		plt.savefig(file_path,dpi=350)
		#plt.show()
		plt.clf()

	def draw_protocolmap(self):
		#print test
		file_path ="./result/" + str(self.casename)
		if( not os.path.exists(file_path)):
			os.makedirs(file_path)


		max_y = max(self.protocol_y)
		maxindex = self.protocol_y.index(max_y)
		lengthOfAxis = len(self.protocol_y)
		xPos = (maxindex/lengthOfAxis)

		if xPos < 0.2:
			xPos += 0.1
		elif xPos > 0.8:
			xPos-=0.1
		else:
			xPos +=0.1

		#print self.protocol_x
		self.protocol_x[self.protocol_x.index('')] = "Other Protocols"

		#print self.protocol_start,self.protocol_end
		file_path += "/protocolmap.png"
		#print file_path, self.protocol_x, self.protocol_y
		plt.title("Packets Protocol Statistics")
		#plt.xlim([self.protocol_start,self.protocol_end])
		plt.ylim([0,max_y + max_y*2/3])
		plt.plot(self.protocol_x,self.protocol_y, "ro")
		#plt.bar(self.protocol_x,self.protocol_y)
		plt.ylabel('Number of packets')
		plt.xlabel('protocol')
		#plt.annotate('MAX packets', xy = (self.protocol_x[maxindex],max_y), xytext = (xPos, 0.6), textcoords = ('axes fraction'), fontsize = 14 ,arrowprops=dict(arrowstyle="->",alpha=1))

		plt.grid(True)
		plt.legend(loc=2)
		#plt.show()
		plt.savefig(file_path,dpi=350)
		plt.clf()
		