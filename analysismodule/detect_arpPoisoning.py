"""

detectarp Poisoning
Created by Kwon min Hyeok
Last modified: 2017-10-24

"""


def detectarpPoisoning(packets):
	arpTable = {}
	detected = {}
	for each_pkt in packets:
		#print arpTable, detected
		if(each_pkt[2] and (each_pkt[2] in arpTable)):
			if(not each_pkt[6] in arpTable[each_pkt[2]]):
				arpTable[each_pkt[2]].append(each_pkt[6])
				detected[each_pkt[2]] = arpTable[each_pkt[2]]
		else:
			arpTable[each_pkt[2]] = [each_pkt[6]]
		if(each_pkt[3] and (each_pkt[3] in arpTable)):
			if(not each_pkt[7] in arpTable[each_pkt[3]]):
				arpTable[each_pkt[3]].append(each_pkt[7])
				detected[each_pkt[3]] = arpTable[each_pkt[3]]
		else:
			arpTable[each_pkt[3]] = [each_pkt[7]]

	#print "ARP", detected
	#print arpTable
	return detected