#!/usr/bin/env python3

import pyshark
import sys
import time
from datetime import datetime
import math
import matplotlib.pyplot as plt
import pyfiglet
#######################
# use ascii text
ascii_banner=pyfiglet.figlet_format("loOkiNg 4 HacKerS")
print(ascii_banner)	
#######################	
####### Initial pcap scan #######
def synport(cap):
	all_ips = {} #Dictionary of all IP information captured from scan.
	syn_count = 0
	sus_packs = []
	for packet in cap:
		try:
			src = packet['ip'].src
			dst = packet['ip'].dst
			src_flag = packet['tcp'].flags
			dst = packet['ip'].dst
			dst_port = packet['tcp'].dstport
			numb = packet.number.show
			#Analyze if packet is a syn packet                     
			if src_flag == '0x00000002':
				if src not in all_ips:
					all_ips[src] = {}
					all_ips[src]['syn'] = 1
					all_ips[src]['ports'] = []
					all_ips[src]['packs'] = []
					all_ips[src]['packs'].append(numb)
					all_ips[src]['dst'] = []
					all_ips[src]['dst'].append(dst)
           
				elif src in all_ips:
					all_ips[src]['syn'] += 1
					all_ips[src]['ports'].append(dst_port)
					all_ips[src]['packs'].append(numb)
					all_ips[src]['dst'].append(dst)

		except:
			pass
###### Analyzing IP Dictionary statistics and funneling for anamolies ######
	for ip in all_ips:
		# print('Accessing all malicious IP Activity')

		uniq_p = len(all_ips[ip]['ports'])
		ssh_count = all_ips[ip]['ports'].count('22')
		ftp_count = all_ips[ip]['ports'].count('20') + all_ips[ip]['ports'].count('21')
####### If the IP scanned over 100 Unique ports, flag as suspicious #######
		if uniq_p > 100:
			print('Possible Port Scan from IP: ' + ip)
			print('{0} unique ports have been scanned'.format(uniq_p))
			pack_1 = all_ips[ip]['packs'][0]
			pack_2 = len(all_ips[ip]['packs']) - 1
			print('Suspicious Packets: {0} ==> {1}'.format(pack_1,pack_2))
			victim = all_ips[ip]['dst'][25]
			print('Possible Victim IP: {0}'.format(victim))
##### Nmap scan type processsor ########
		if uniq_p > 900:
			print("Nmap Scan Type: Top 1000")
		elif uniq_p > 500:
			print("Nmap Scan Type: Top 500")
		elif uniq_p >= 100:
			print("Nmap Scan Type: Top 100")

 ######SSH Brute Force counter #######   
		if ssh_count > 15:
			print("Possible SSH Brute Force Detected")
			print("{0} has failed to login {1} times".format(ip, ssh_count))

		if ftp_count > 15:
			print("Possible FTP Brute Force Detected")
			print("{0} has failed to login {1} times".format(ip, ftp_count))
	print("\n")	
	print("============================================================")
	print("\n")

### Goal: segment pcap file into equal or near-equal blocks ###

# define a function that returns all packets
def all_packets_ftp(cap, block_size):
	q = block_size
	# initialize list of all packet numbers
	pkts = []
	# initialize list of all timestamps
	timestamps = []
	# initialize list of ftp-existence list
	ftp_exist = []
	# loop through packets in capture file, one by one
	for packet in cap:	
		try:		
			# find pcap-generated packet ordinal number	
			numb = packet.number.show
			# append associated packet ordinal number			
			pkts.append(numb)
			# define packet timestamp
			src_time = packet.sniff_timestamp
			# append associated timestamp
			timestamps.append(src_time)
			### create list of 1s and 0s that correspond to existence of ftp request
			### ftp requests are separated into Client & Server
			### 	So add focus on attacker	
			# pull out ftp protocol markers
			if str(packet.tcp.dstport) == '20' or str(packet.tcp.dstport)=='21':
				ftp_exist.append('1')			
			else:
				ftp_exist.append('0')
				pass

		except AttributeError:
			ftp_exist.append('0')			
			pass
	a = pkts
	#print("all packets:", a)
	b = timestamps # datetime.datetime objects
	#print("Timestamps:", b)
	d = ftp_exist
	#print("ftp Existence:", d)
	### replace each datetime.datetime list object 
	### with difference of that list object with first list object
	c = []
	c.append(float(0))
	[c.append(float(b[i]) - float(b[0])) for i in range(1,len(b))]
	#print("Relative Timestamps:", c)
	
	# Count number of ftp requests in whole packet
	Num_ftp = ftp_exist.count('1')
	#print(Num_ftp)
	# calculate whole pcap packet range
	pcap_range = f"{a[0]} -> {a[-1]}"
	# calculate time elapsed for entire pcap
	pcap_time_range = c[-1] - c[0]
	# calculate pcap ftp density
	pcap_ftp_density = Num_ftp/pcap_time_range
	# calculate probability of finding ftp request in whole packet
	Prob_whole = Num_ftp / len(ftp_exist)
	# calculate entropy of whole capture file
	#Entr_whole = -(Prob_whole * math.log((Prob_whole),2))
	# calculate entropy density per time for pcap
	#Entr_pcap_density = Entr_whole/pcap_time_range
	# print number of ftps in, probability of ftps in, and entropy of: whole capture file
	print("\n")	
	print("============================================================")
	print("\n")
	print(f"Number of ftp Requests in PCAP: {Num_ftp}")
	print(f"pcap_range is {pcap_range}")
	print(f"Time elapsed for this pcap is: {pcap_time_range} seconds")
	print(f"ftp density per time for this pcap is {pcap_ftp_density}")
	print(f"Probability of ftp Requests in PCAP: {Prob_whole}")
	#print(f"Entropy of PCAP: {Entr_whole}")
	#print(f"Entropy density per time for PCAP is: {Entr_pcap_density}")
	print("\n")	
	print("============================================================")
	print("\n")
	######################
	######################
	### From beginning of packet capture	
	### take consecutive 1/q% increment block segments of ftp requests
	### and analyze each block segment individually
	### if not suspicious: discard, and move to next block
	### if suspicious: give alert, and move to next block
	#######################
	# segment automatically
	pcap_length = int(len(a)+1)
	# WARNING: leaves off ending packets if pcap not divisible by q (number chosen)
	# FIXED in lines 147 -> 160
	block_size = int(math.floor(len(a)/q)) # make block size to be user-defined input *SAME FOR LINE 124*
	# initialize graph x values
	x = []	
	# initialize graph y values
	y = []
	# initialize graph z values
	z = []	
	# initialize running total of pcap length
	running_total = 0
	# intialize counter to keep track of what block loop is on
	count = 0
	for element in range(block_size, pcap_length, block_size):
		sub_block=list(range(element-block_size,element)) 
		#print("current sub_block is:", sub_block)
		
		ftp_block = a[element-block_size:element]
		#print("current ftp_block is:", ftp_block)
		
		time_block = c[element-block_size:element]
		#print("current time_block is:", time_block)
		
		ftp_exist_block  = d[element-block_size:element]
		#print("current ftp_exist_block is:", ftp_exist_block)
		
		running_total += len(ftp_block)
		count += 1
		extra = len(a) - running_total
		### if total length of all blocks does not equal length of pcap file
		if running_total != len(a) and count == int(q): # make count to be user-defined input *SAME FOR LINE 96*
			### then append the missing packets to the most recent block
			for nums in a[-(extra):]:
				ftp_block.append(nums)
			### same for missing "ones" in ftp existence block
			for nims in d[-(extra):]:
				ftp_exist_block.append(nims)
			### same for missing time block
			for noms in c[-(extra):]:
				time_block.append(noms)
			try: 
				len(ftp_block)==len(ftp_exist)==len(time_block)
			except:
				break
			
		Num_ftp_sub = ftp_exist_block.count('1')
		#print(f"Number of ftp Requests in block: {Num_ftp_sub}")
		
		packet_range = f"{ftp_block[0]} -> {ftp_block[-1]}"
		#print(f"packet_range is {packet_range}")

		time_range = time_block[-1] - time_block[0]
		#print(f"Time elapsed for this block is: {time_range}")
		
		ftp_density = Num_ftp_sub/time_range
		#print(f"ftp density per time for this block is {ftp_density}")

		Prob_block = Num_ftp_sub / len(ftp_block)
		#print(f"Probability of ftp Requests in block: {Prob_block}")
		
		try:
			Entr_block = -(Prob_block * math.log((Prob_block),2))
			#print(f"Entropy of block: {Entr_block}")
			Entr_density = Entr_block/time_range
			#print(f"Entropy density per time for this block is {Entr_density}")
		except ValueError:
			Entr_block = 0
			#print(f"Entropy of block: {Entr_block}")
			Entr_density = 0
			#print(f"Entropy density per time for this block is {Entr_density}")
		except:
			pass
		#print("\n")

		######################
		######################
		### make probability graph with x values to be packet numbers
		### and y values to be ftp_density per time
		### entropy graph with x values to be packet numbers
		### and z values to be entropy density per time
		######################
		### add plotting here
		x.append(ftp_block[-1])
		y.append(ftp_density)
		#z.append(Entr_density)
		######################
		
	######################
	global t 
	t = x
	global u
	u = y
	#print(t, 't')
	#print(u, 'u')
	
def all_packets_ssh(cap, block_size):
	q = block_size
	# initialize list of all packet numbers
	pkts = []
	# initialize list of all timestamps
	timestamps = []
	# initialize list of ssh-existence list
	ssh_exist = []
	# loop through packets in capture file, one by one
	for packet in cap:	
		try:		
			# find pcap-generated packet ordinal number	
			numb = packet.number.show
			# append associated packet ordinal number			
			pkts.append(numb)
			# define packet timestamp
			src_time = packet.sniff_timestamp
			# append associated timestamp
			timestamps.append(src_time)
			### create list of 1s and 0s that correspond to existence of ssh request
			### SSH requests are separated into Client & Server
			### 	So add focus on attacker	
			# pull out ssh protocol markers
			if str(packet.tcp.dstport) == '22':
				ssh_exist.append('1')			
			else:
				ssh_exist.append('0')
				pass

		except AttributeError:
			pass
	a = pkts
	#print("all packets:", a)
	b = timestamps # datetime.datetime objects
	#print("Timestamps:", b)
	d = ssh_exist
	#print("ssh Existence:", d)
	### replace each datetime.datetime list object 
	### with difference of that list object with first list object
	c = []
	c.append(float(0))
	[c.append(float(b[i]) - float(b[0])) for i in range(1,len(b))]
	#print("Relative Timestamps:", c)
	
	# Count number of SSH requests in whole packet
	Num_ssh = ssh_exist.count('1')
	#print(Num_ssh)
	# calculate whole pcap packet range
	pcap_range = f"{a[0]} -> {a[-1]}"
	# calculate time elapsed for entire pcap
	pcap_time_range = c[-1] - c[0]
	# calculate pcap ssh density
	pcap_ssh_density = Num_ssh/pcap_time_range
	# calculate probability of finding SSH request in whole packet
	Prob_whole = Num_ssh / len(ssh_exist)
	# calculate entropy of whole capture file
	#Entr_whole = -(Prob_whole * math.log((Prob_whole),2))
	# calculate entropy density per time for pcap
	#Entr_pcap_density = Entr_whole/pcap_time_range
	# print number of SSHs in, probability of SSHs in, and entropy of: whole capture file
	print(f"Number of SSH Requests in PCAP: {Num_ssh}")
	print(f"pcap_range is {pcap_range}")
	print(f"Time elapsed for this pcap is: {pcap_time_range} seconds")
	print(f"ssh density per time for this pcap is {pcap_ssh_density}")
	print(f"Probability of SSH Requests in PCAP: {Prob_whole}")
	#print(f"Entropy of PCAP: {Entr_whole}")
	#print(f"Entropy density per time for PCAP is: {Entr_pcap_density}")
	print("\n")	
	print("============================================================")
	print("\n")
	######################
	######################
	### From beginning of packet capture	
	### take consecutive 1/q% (or other) increment block segments of ssh requests
	### and analyze each block segment individually
	### if not suspicious: discard, and move to next block
	### if suspicious: give alert, and move to next block
	#######################
	# segment automatically
	pcap_length = int(len(a)+1)
	# WARNING: leaves off ending packets if pcap not divisible by q (number chosen)
	# FIXED in lines 147 -> 160
	block_size = int(math.floor(len(a)/q)) # make block size to be user-defined input
	# initialize graph x values
	x = []	
	# initialize graph y values
	y = []
	# initialize graph z values
	z = []	
	# initialize running total of pcap length
	running_total = 0
	# intialize counter to keep track of what block loop is on
	count = 0
	for element in range(block_size, pcap_length, block_size):
		sub_block=list(range(element-block_size,element)) 
		#print("current sub_block is:", sub_block)
		
		ssh_block = a[element-block_size:element]
		#print("current ssh_block is:", ssh_block)
		
		time_block = c[element-block_size:element]
		#print("current time_block is:", time_block)
		
		ssh_exist_block  = d[element-block_size:element]
		#print("current ssh_exist_block is:", ssh_exist_block)
		
		running_total += len(ssh_block)
		count += 1
		extra = len(a) - running_total
		### if total length of all blocks does not equal length of pcap file
		if running_total != len(a) and count == q: # make count to be user-defined input
			### then append the missing packets to the most recent block
			for nums in a[-(extra):]:
				ssh_block.append(nums)
			### same for missing "ones" in ssh existence block
			for nims in d[-(extra):]:
				ssh_exist_block.append(nims)
			### same for missing time block
			for noms in c[-(extra):]:
				time_block.append(noms)
			try: 
				len(ssh_block)==len(ssh_exist)==len(time_block)
			except:
				break
			
		Num_ssh_sub = ssh_exist_block.count('1')
		#print(f"Number of SSH Requests in block: {Num_ssh_sub}")
		
		packet_range = f"{ssh_block[0]} -> {ssh_block[-1]}"
		#print(f"packet_range is {packet_range}")

		time_range = time_block[-1] - time_block[0]
		#print(f"Time elapsed for this block is: {time_range}")
		
		ssh_density = Num_ssh_sub/time_range
		#print(f"ssh density per time for this block is {ssh_density}")

		Prob_block = Num_ssh_sub / len(ssh_block)
		#print(f"Probability of SSH Requests in block: {Prob_block}")
		
		try:
			Entr_block = -(Prob_block * math.log((Prob_block),2))
			#print(f"Entropy of block: {Entr_block}")
			Entr_density = Entr_block/time_range
			#print(f"Entropy density per time for this block is {Entr_density}")
		except ValueError:
			Entr_block = 0
			#print(f"Entropy of block: {Entr_block}")
			Entr_density = 0
			#print(f"Entropy density per time for this block is {Entr_density}")
		except:
			pass
		#print("\n")

		######################
		######################
		### make probability graph with x values to be packet numbers
		### and y values to be ssh_density per time
		### entropy graph with x values to be packet numbers
		### and z values to be entropy density per time
		######################
		### add plotting here
		#x.append(ssh_block[-1])
		y.append(ssh_density)
		#z.append(Entr_density)
		######################
		
	######################
	global v
	v = y
	#print(v, 'v')

def all_packets_syn(cap, block_size):
	q = block_size
	# initialize list of all packet numbers
	pkts = []
	# initialize list of all timestamps
	timestamps = []
	# initialize list of syn-existence list
	syn_exist = []
	# loop through packets in capture file, one by one
	for packet in cap:	
		try:		
			# find pcap-generated packet ordinal number	
			numb = packet.number.show
			# append associated packet ordinal number			
			pkts.append(numb)
			# define packet timestamp
			src_time = packet.sniff_timestamp
			# append associated timestamp
			timestamps.append(src_time)
			### create list of 1s and 0s that correspond to existence of SYN request
			### SYN requests naturally filter out response flags,
			### 	allowing focus on attacker	
			# pull out tcp protocol flag
			tcp_src_flag = packet['tcp'].flags
			# if protocol flag is a SYN
			if tcp_src_flag == '0x00000002':
				# append 1			
				syn_exist.append('1')
			# if not a SYN flag
			else:
				# append 0
				syn_exist.append('0')
		except AttributeError:
			# pull out udp protocol flag
			udp_src_flag = packet.udp
			syn_exist.append('0')	
		
		except:
			pass
	a = pkts
	#print("all packets:", a)
	b = timestamps # datetime.datetime objects
	#print("Timestamps:", b)
	d = syn_exist
	#print("Syn Existence:", d)
	### replace each datetime.datetime list object 
	### with difference of that list object with first list object
	c = []
	c.append(float(0))
	[c.append(float(b[i]) - float(b[0])) for i in range(1,len(b))]
	#print("Relative Timestamps:", c)
	
	# Count number of SYN requests in whole packet
	Num_syn = syn_exist.count('1')
	# calculate whole pcap packet range
	pcap_range = f"{a[0]} -> {a[-1]}"
	# calculate time elapsed for entire pcap
	pcap_time_range = c[-1] - c[0]
	# calculate pcap syn density
	pcap_syn_density = Num_syn/pcap_time_range
	# calculate probability of finding SYN request in whole packet
	Prob_whole = Num_syn / len(syn_exist)
	# calculate entropy of whole capture file
	Entr_whole = -(Prob_whole * math.log((Prob_whole),2))
	# calculate entropy density per time for pcap
	Entr_pcap_density = Entr_whole/pcap_time_range
	# print number of SYNs in, probability of SYNs in, and entropy of: whole capture file
	print(f"Number of SYN Requests in PCAP: {Num_syn}")
	print(f"pcap_range is {pcap_range}")
	print(f"Time elapsed for this pcap is: {pcap_time_range} seconds")
	print(f"syn density per time for this pcap is {pcap_syn_density}")
	print(f"Probability of SYN Requests in PCAP: {Prob_whole}")
	#print(f"Entropy of PCAP: {Entr_whole}")
	#print(f"Entropy density per time for PCAP is: {Entr_pcap_density}")
	print("\n")	
	print("============================================================")
	print("\n")
	######################
	######################
	### From beginning of packet capture	
	### take consecutive q% increment block segments of syn requests
	### and analyze each block segment individually
	### if not suspicious: discard, and move to next block
	### if suspicious: give alert, and move to next block
	#######################
	# segment automatically
	pcap_length = int(len(a)+1)
	# WARNING: leaves off ending packets if pcap not divisible by q
	# FIXED in lines 174 -> 188
	block_size = int(math.floor(len(a)/q)) 
	# initialize graph x values
	x = []	
	# initialize graph y values
	y = []
	# initialize graph z values
	z = []	
	# initialize running total of pcap length
	running_total = 0
	# intialize counter to keep track of what block loop is on
	count = 0
	for element in range(block_size, pcap_length, block_size):
		sub_block=list(range(element-block_size,element)) 
		#print("current sub_block is:", sub_block)
		
		syn_block = a[element-block_size:element]
		#print("current syn_block is:", syn_block)
		
		time_block = c[element-block_size:element]
		#print("current time_block is:", time_block)
		
		syn_exist_block  = d[element-block_size:element]
		#print("current syn_exist_block is:", syn_exist_block)
		
		running_total += len(syn_block)
		count += 1
		extra = len(a) - running_total
		### if total length of all blocks does not equal length of pcap file
		if running_total != len(a) and count == q:
			### then append the missing packets to the most recent block
			for nums in a[-(extra):]:
				syn_block.append(nums)
			### same for missing "ones" in syn existence block
			for nims in d[-(extra):]:
				syn_exist_block.append(nims)
			### same for missing time block
			for noms in c[-(extra):]:
				time_block.append(noms)
			try: 
				len(syn_block)==len(syn_exist)==len(time_block)
			except:
				break
			
		Num_syn_sub = syn_exist_block.count('1')
		#print(f"Number of SYN Requests in block: {Num_syn_sub}")
		
		packet_range = f"{syn_block[0]} -> {syn_block[-1]}"
		#print(f"packet_range is {packet_range}")

		time_range = time_block[-1] - time_block[0]
		#print(f"Time elapsed for this block is: {time_range}")
		
		syn_density = Num_syn_sub/time_range
		#print(f"syn density per time for this block is {syn_density}")

		Prob_block = Num_syn_sub / len(syn_block)
		#print(f"Probability of SYN Requests in block: {Prob_block}")
		
		try:
			Entr_block = -(Prob_block * math.log((Prob_block),2))
			#print(f"Entropy of block: {Entr_block}")
			Entr_density = Entr_block/time_range
			#print(f"Entropy density per time for this block is {Entr_density}")
		except ValueError:
			Entr_block = 0
			#print(f"Entropy of block: {Entr_block}")
			Entr_density = 0
			#print(f"Entropy density per time for this block is {Entr_density}")
		except:
			pass
		#print("\n")

		######################
		######################
		### make probability graph with x values to be packet numbers
		### and y values to be syn_density per time
		### entropy graph with x values to be packet numbers
		### and z values to be entropy density per time
		######################
		### add plotting here
		#x.append(syn_block[-1])
		y.append(syn_density)
		#z.append(Entr_density)
		######################
	
	######################
	global w
	w = y
	#print(w, 'w')

def print_func():
	#######################
	# print all 3 outputs 
	plt.subplot(3,1,1)
	max_y = (1.25)*max(max(u),max(v),max(w))
	plt.ylim(0,max_y)
	plt.bar(t,u, align='edge', width=-1.0, alpha=0.5, label = 'Inbound FTP Density per time')
	plt.legend(loc='best')

	plt.subplot(3,1,2)
	plt.ylim(0,max_y)
	plt.bar(t,v, align='edge', width=-1.0, alpha=0.5, label = 'Inbound SSH Density per time')
	plt.legend(loc='best')

	plt.subplot(3,1,3)
	plt.ylim(0,max_y)
	plt.bar(t,w, align='edge', width=-1.0, alpha=0.5, label = 'Inbound SYN Density per time')
	plt.legend(loc='best')
	
	plt.xlabel('Packet Ranges')
	out = plt.show()
	
######################
### Run Program
######################
if __name__ == "__main__":
	# start timer
	begin = time.time()	
	# take user input and output to file variable
	f = sys.argv[1]
	cap = pyshark.FileCapture(f)
	#######################
	# check for .pcap ending
	if f.lower().endswith(('.pcap','.pcapng')):
		# run synport function
		synport(cap)
		# add user defined granularity
		
		p = 0
		while p <= 1:
			p = int(input("Enter integer number of sub-divisions for FTP/SSH/SYN graphs: "))
			if p == 0:		
				print("please input a positive value")
			elif p == 1:
				print("please choose at least 2 sub-divisions")
			elif p > 1:		
				# run ftp_packets function	
				all_packets_ftp(cap,p)
				# run ssh_output function	
				all_packets_ssh(cap,p)
				# run syn_output function
				all_packets_syn(cap,p)
				# end timer
				end = time.time()
				# show runtime
				print(f"Hackers found in {end - begin} seconds")
				# run print function
				print_func()
	else:
		print("Please input a pcap or pcapng file")
	
