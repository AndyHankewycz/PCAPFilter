#July 9, 2015

#Imports
import sys
import os
from pcapfile import savefile
from pcapfile.protocols.linklayer import ethernet
from pcapfile.protocols.network import ip
import binascii

# Global constants
path = os.getcwd()

# Global variables
pcapFileNames = []	# list of pcap file names to parse
foundIPs = []		# dictionary to store found IPs for each pcap entered
ignoredIPs = []		# list of ips to be ignored

# parse the pcap file given by pcapIndex for the packets around timestamp
# returning new pcap filename
def parsePcapFile(pcapFileName, pcapIndex):
	# open the pcap file for reading
	pcap_file_f = open(path + "/" + pcapFileName)
	capfile = savefile.load_savefile(pcap_file_f, verbose=True)

	for pkt in capfile.packets:
		eth_frame = ethernet.Ethernet(pkt.raw())
	  	eth_type = eth_frame.type
	  	if(eth_type == 2048):
			ip_packet = ip.IP(binascii.unhexlify(eth_frame.payload))
			# foundIPs[pcapFileName][ip_packet.dst] = ip_packet.dst	# push ip into table
			foundIPs[pcapIndex][ip_packet.dst] = 1	# push ip into table
	pcap_file_f.close()		# close file descriptor

def findMatches():
	# foundIPs is an array of dictionaries, [pcap]{ip}
	# iterating over each ip in first pcap
	for ip1 in foundIPs[0]:
		# iterate over each ip in each of the other pcaps
		for pcap2 in foundIPs[1:]:
			for ip2 in pcap2:
				if(ip1 == ip2):
					foundIPs[0][ip1] = foundIPs[0][ip1] + 1

def printMatchingIPs():
	print "\nIP addresses found within all files"
	print "-----------------------------------"
	for ip in foundIPs[0]:
		# compare the count with the number of pcap files, to check if the
		# ip was found in each pcap
		if(foundIPs[0][ip] >= len(foundIPs) and checkExclusions(ip)):
			print ip
	print "-----------------------------------"

def checkExclusions(ip):
	if(len(ignoredIPs) > 0):
		for ignore in ignoredIPs:
			if(ip == ignore):
				return False
	return True

def parseCmdArgs():
	global pcapFileNames
	skipNext = False	# if an option takes another arg, it needs to be skipped
	if(len(sys.argv) > 1):
		i = 1
		while i < len(sys.argv):
			# check if the argument is '-' followed by 1 char
			if(skipNext):
				skipNext = False
				i = i + 1
				continue
			if(len(sys.argv[i]) == 2):
				# use switch statment here
				if(sys.argv[i] == '-x'):
					# check that there is a filename following the option
					if(i < len(sys.argv) - 1):
						skipNext = True
						importExclusionsList(sys.argv[i + 1])
					else:
						print "-- No exclusion list specified"
				else:
					print "-- option %s is not recognized" % sys.argv[i]
			else:
				# if its not an option it should be a pcap file
				print "found a pcap %s" % sys.argv[i]
				pcapFileNames.append(sys.argv[i])
				# add a dictionary for this pcaps ips
				foundIPs.append(dict())
			i = i + 1

	if(len(pcapFileNames) < 1):
		print "Please provide 1 or more pcap files for analysis\n"
		endProgram()

def importExclusionsList(fileName):
	print "importing %s" % fileName
	exclusionFile = open(path + "/" + fileName, "r")
	ip = exclusionFile.readline()
	while(ip != ""):
		# push the ip into the list, dropping the trailing new line
		ignoredIPs.append(ip[:len(ip)-1])
		ip = exclusionFile.readline()

def endProgram():
	sys.exit()

# ---------- Begin Main ----------

# check for input files and any command line options
parseCmdArgs()

i = 0
while i < len(pcapFileNames):
	parsePcapFile(pcapFileNames[i], i)
	i = i + 1
	#pcap_files.append(fileName)

findMatches()
printMatchingIPs()

endProgram()

# ---------- End Main ----------
