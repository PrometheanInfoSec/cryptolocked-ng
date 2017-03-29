#!/usr/bin/env python
"""
cryptolocked version 2.0 12/25/2016

Command line arguments
for debug mode (functionality check): --debug
to arm from the command line: --armed
to arm hunter module only: --only-arm-hunter
for tentacles (see below): --tentacles
to disable failsafe: --no-failsafe
to diable hunter module: --no-hunter
"""

import random
import os
import sys
import time
import hashlib
import signal
import smtplib
import argparse
import threading
import subprocess


#This points to the global configuration file
confphile = "cl.conf"

class hunter:
	hunterfiles = []
	lockeddict = {}

	cl = None

	osname = None
	
	def __init__(self, cl=None):
		self.cl = cl

		
		try:
                        self.cl.check_loaded()
                except:
                        print "Hunter needs a global instance of cryptolocked"
                        print "It should be called 'cl'"
                        print "Exiting.."
                        sys.exit(-1)


		if os.name == 'posix' and subprocess.call('which lsof 1>/dev/null 2>/dev/null', shell=True) != 0:
			print "Something went wrong locating the lsof binary"
			print "The hunter module cannot continue"
			print "Disable hunter in the config file"
			print "Exiting.."
			sys.exit(-1)
		
		if os.name == 'nt':
			self.osname = 'nt'
		
		if os.name == "posix":
			self.osname = "posix"
		
		if self.osname is None:
			print "Unsupported OS detected"
			print "Exiting.."
			sys.exit(-1)
		
		
		
		if not os.path.exists(self.cl.conf['hunterphile']):
			print "Something went wrong locating the hunterphile: %s" % (self.cl.conf['hunterphile'])
			print "Hunter cannot continue"
			print "Exiting.."
			sys.exit(-1)

		
		
		fi = open(self.cl.conf['hunterphile'], "r")
		data = fi.read()
		fi.close()

		print
		print "-- Hunter instantiated --"

		for line in data.split("\n"):
			if len(line) < 1 or line[0] == "#":
				continue
			if ":::" not in line:
				self.hunterfiles.append(line)
				print "Hunter tracking file: %s" % line
			else:
				self.lockeddict[line.split(":::")[0]] = line.split(":::")[1]
				self.hunterfiles.append(line.split(":::")[0])
				print "Hunter protecting file: %s" %line.split(":::")[0], "\n\twith KeyFile of: %s\n" %line.split(":::")[1]
	
	def loop(self):
		if self.osname == "nt":
			self.win_loop()
		elif self.osname == "posix":
			self.lin_loop()
	
	def win_loop(self):
		while True:
		
			filepidlist = self.parse_winfiles()
			#print filepidlist
			count = 0
			for handle in filepidlist:
				for fii in self.hunterfiles:	
					if fii in handle:
						protectedfilekey = self.lockeddict.get(fii)
						if protectedfilekey == "None":
							pass
						else:
							if protectedfilekey in filepidlist:
								print "Process PID [%s] has opened a locked file [%s] but was not terminated as Key file [%s] was open" %(filepidlist[handle], fii, protectedfilekey)
								continue
						if self.cl.conf['armed_state'] or self.cl.conf['only_arm_hunter']:
							subprocess.call("taskkill /pid %s" %str(filepidlist[handle]), shell=True)
							print "Process PID [%s] has been killed for attempting to access the hunter tracked file [%s]" %(filepidlist[handle], fii)
						else:
							print "Process PID [%s] accessed file [%s] but cryptolocked.hunter is not armed so no actions were taken" %(filepidlist[handle], fii)
				count += 1
	
	def parse_winfiles(self):
		pid = None
		filepidlist = {}
		time.sleep(self.cl.conf['hunter_pause'])
		output = subprocess.check_output("assets\\handle.exe", shell=True)
		for line in output.split("\n"):
			if "pid:" in line:
				pid = line.split()[2]
				#print pid
			if len(line) == 0:
				continue
			if len(line.split("File")) != 2:
				continue	
			filepidlist[line.split("File")[1].strip()] = pid 
		return filepidlist
	
	def lin_loop(self):
		while True:
			lsoflist = self.parse_lsof()
			count = 0
			for filename in lsoflist[0]:
				for fii in self.hunterfiles:
					if fii == filename:
						protectedfilekey = self.lockeddict.get(fii)
						if protectedfilekey == "None":
							pass
						else:
							if protectedfilekey in lsoflist[0]:
								print "Process PID [%s] has opened a locked file [%s] but was not terminated as Key file [%s] was open" %(filepidlist[handle], fii, protectedfilekey)
								continue	
						if self.cl.conf['armed_state'] or self.cl.conf['only_arm_hunter']:
							subprocess.call("kill -9 %s" %lsoflist[1][count], shell=True)
							print "Process PID [%s] has been killed for attempting to access the hunter tracked file [%s]" % (lsoflist[1][count], fii)
						else:
							print "Process PID [%s] accessed file [%s] but cryptolocked.hunter is not armed so no actions were taken" % (lsoflist[1][count], fii)
				count += 1

	def parse_lsof(self):
		lsoflist = [[],[]]
		time.sleep(self.cl.conf['hunter_pause'])
		output = subprocess.check_output("lsof 2>/dev/null", shell=True)
		for line in output.split("\n"):
			if len(line) == 0:
				continue
			else:
				lsoflist[0].append(line.split()[-1])
				lsoflist[1].append(line.split()[1])
		return lsoflist
                
class tentacles:
	filename = []
	content = []
	hhash = []

	tentaphile = None

	created_files = []

	cl = None

	def __init__(self, cl=None):
		self.cl = cl

		try:
			self.cl.check_loaded()
		except:
			print "Tentacles needs a global instance of cryptolocked"
			print "It should be called 'cl'"
			print "Exiting.."
			sys.exit(-1)


		self.tentaphile = self.cl.conf['tentaphile']
	
		try:
			fi = open(self.tentaphile, "r")
			data = fi.read()
			fi.close()
			for line in data.split("\n"):
				if len(line) == 0 or line[0] == "#":
					continue
				self.filename.append(line.strip())
		except:
			print "Something went wrong trying to read the tentaphile: %s" % (tentaphile)
			print "Exiting.."
			sys.exit(-1)
	
		print 
		print "-- Tentacles instantiated --"
		for i in xrange(len(self.filename)):
			
			
			if not self.cl.file_exists(self.filename[i]):
				print "Creating tripfile: %s" % (self.filename[i])			

				self.content.append(self.cl.rand_data())
				self.hhash.append(hashlib.md5(self.content[i]).hexdigest())
				self.cl.create_file(self.filename[i], self.content[i], self.hhash[i])
				self.created_files.append(self.filename[i])

			else:
				print "Tracking tripfile: %s" % (self.filename[i])
				self.content.append("NULL")
				fi = open(self.filename[i])
				data = fi.read()
				fi.close()
				temph = hashlib.md5(data).hexdigest()

				self.hhash.append(temph)

	#The main loop
        #checks for file integrity violations and file destruction
        def loop(self):
		while True:
			for i in xrange(len(self.filename)):
				if not self.cl.file_exists(self.filename[i]):
					print "FILE DESTRUCTION", self.filename[i]
					self.cl.countermeasures()

				if not self.cl.file_integrity(self.filename[i], self.hhash[i]):
					print "INTEGRITY FAIL", self.filename[i]
					self.cl.countermeasures()

			time.sleep(self.cl.conf['tentacles_pause'])

	def cleanup(self):
		for fin in self.created_files:
			self.cl.destroy_file(fin)

		print "# Tentacles has cleaned up all created files"
			


class cryptolocked:

	permissive_conf = False

	conf = {}
	conf['tentacles'] = [None,'bool']
	conf['tentaphile'] = [None,'string']

	conf['hunter'] = [None, 'bool']
	conf['hunterphile'] = [None,'string']
	conf['tentacles_pause'] = [None,'int']
	conf['hunter_pause'] = [None,'int']

	conf['armed_state'] = [None,'bool']
	
	#conf['filename'] = [None,'string']
	#conf['content'] = [None,'string']
	#conf['hhash'] = [None,'string']

	#conf['hunterfiles'] = [None,'string']
	conf['no_hunter'] = [None,'bool']
	conf['no_failsafe'] = [None,'bool']
	
	conf['only_arm_hunter'] = [None,'bool']

	conf['fromaddr'] = [None, 'string']
	conf['toaddr'] = [None, 'string']
	conf['username'] = [None, 'string']
	conf['password'] = [None, 'string']
	
	conf['sensitive_alerts'] = [None, 'bool']

	conf['alerts_enabled'] = [None, 'bool']

	

	t = None
	h = None

	tthread = None
	hthread = None


	#duplicated
	filename = []
	hhash = []
	content = []


	def cnv_int(self, inp):
		return int(inp)


	def cnv_str(self, inp):
		return str(inp)
	
	def cnv_bool(self, inp):
		inp = inp.lower()
		return inp == "true"

	def cli_override(self, one, two):
		if one not in self.conf.keys():
			print "!! Error in cli override"
			print "!! Variable does not exist"
			return False

		if type(self.conf[one]) != list and self.conf[one][0] != None:
			print "!! Error in cli override"
			print "!! Variable is already set"
			return False

		two = str(two)

		self.conf[one][0] = two
		
	def read_conf(self):
		for key in self.conf.keys():
			print "%s: %s" % (key, self.conf[key])

	def conf_types(self):
	
		cnv_map = {'bool':self.cnv_bool,'string':self.cnv_str,'int':self.cnv_int}
	
		for key in self.conf.keys():
			if self.conf[key][0] == None:
				raise Exception("Something is wrong with the configuration")
			
			self.conf[key] = cnv_map[self.conf[key][1]](self.conf[key][0])


	def __init__(self, overrides=None, debug=None):
		if debug is not None:
			self.functionality_test()

		if not self.file_exists(confphile):
			print "Something went wrong trying to find the conf file"
			print "Edit the confphile variable in this script to point to the correct file."
			print "Exiting.."
			sys.exit(-1)

		if type(overrides) == dict and len(overrides.keys()) > 0:
			for key in overrides.keys():
				self.cli_override(key, overrides[key])


		self.parse_conf()

		

		if self.conf['tentacles']:
			self.t = tentacles(self)
			self.tthread = threading.Thread(target=self.t.loop)
			self.tthread.daemon = True
			self.tthread.start()
		
		if self.conf['hunter']:
			self.h = hunter(self)
			self.hthread = threading.Thread(target=self.h.loop)
			self.hthread.daemon = True
			self.hthread.start()

		#Check if both hunter and tentacles are disabled
		if self.h == None and self.t == None:
			print "No modules loaded"


	def parse_conf(self):
		fi = open(confphile, "r")
		data = fi.read()
		fi.close()

		count = 0
		banner_printed = False
		splitby = "\n"
		#if os.name != "posix":
		#	splitby = "\r\n"
		for line in data.split(splitby):
			count += 1
			if len(line) == 0 or line[0] == "#":
				continue

			ccount = 0
			for c in line:
				if c == ":":
					ccount += 1

			if ccount != 1:
				if not banner_printed:
					print "#####################"
					print "# Conf Parse Errors #"
					print "#####################"
					banner_printed = True
				print "Line %s appears to have an error" % count
				continue


			one, two = line.split(":")
			one = one.strip()
			two = two.strip()

			if one not in self.conf.keys():
				if not banner_printed:
                                        print "#####################"
                                        print "# Conf Parse Errors #"
                                        print "#####################"
					banner_printed = True
				print "Line %s has an error" % count
				print "I don't know how to parse %s" % one
				continue

			if len(two) > 0:
				if self.conf[one][0] == None:
					self.conf[one][0] = two
				else:
					print "# Command line Override"
					print "# Ignoring conf for %s" % one
			else:
				if not banner_printed:
                                        print "#####################"
                                        print "# Conf Parse Errors #"
                                        print "#####################"
					banner_printed = True
				print "Line %s has an error" % count
				print "Variable not set"
				continue

		for key in self.conf.keys():
			if self.conf[key][0] == None:
				if not banner_printed:
                                        print "#####################"
                                        print "# Conf Parse Errors #"
                                        print "#####################"
					banner_printed = True
				print "%s is not set" % key
				continue
			
		if banner_printed:
			print "Exiting.."
			sys.exit(-1)

		
		self.conf_types()


	def send_alert(self, msg):
		server = smtplib.SMTP('smtp.gmail.com:587')
		server.starttls()
		server.login(self.conf['username'],self.conf['password'])
		server.sendmail(self.conf['fromaddr'], self.conf['toaddr'], msg)
		server.quit()
	
	#Removes the file on close
	#This helps hide the presence of cryptolocked
	#It also lessens the likihood of permission errors
	def safe_close(self, signal, frame):
		if self.conf['tentacles']:
			self.t.cleanup()
		sys.exit(0)
	
	#Creates the random data to fill a file with
	def rand_data(self):
		dat = ''
		for i in range(100):
			dat = dat + str(random.randint(1,10000))
		return dat
	
	#Create a file
	def create_file(self, filename, content, hhash):
		if os.path.exists(filename):
			print "ERROR, file already exists", filename
			sys.exit(-1)	
	
		fi = open(filename,'w')
		fi.write(content)
		fi.close()
		if not self.file_integrity(filename, hhash):
			print "ERROR CREATING FILE", filename
			sys.exit(-1)
		
	
	#Destroy a file
	def destroy_file(self, filename):
		try:
			os.remove(filename)
		except:
			print "File was previously erased"
		
	#return whether or not a file exists
	def file_exists(self, filename):
		return os.path.isfile(filename)
		
	#Check the integrity of a file
	def file_integrity(self, filename, hhash):
		fi = open(filename,'r')
		data = fi.read()
		_hash = hashlib.md5(data).hexdigest()
		return hhash == _hash
	
	def functionality_test(self):
		print "Checking if file exists:\t",not self.file_exists(".debugfile")
		fi = open(".debugfile","w")
		fi.close()
		print "Checking if file created:\t", self.file_exists(".debugfile")
		subprocess.Popen('echo 1 > .debugfile', shell=True)

		(a, b) = subprocess.Popen("cat .debugfile", shell=True, stdout=subprocess.PIPE).communicate()
		print "Checking if file written:\t", a.strip() == "1"
		self.destroy_file(".debugfile")
		print "Checking if file destroyed:\t", not self.file_exists(".debugfile")
		print "If all \"True\" functionality is good"
		exit(0)
		return True
		
	#The script's countermeasures
	def countermeasures(self):
		if self.conf['tentacles']:
			self.t.cleanup()

		#I really want a windows version of LSOF here.
		
		#Some possible countermeasures
		#	email alerts
		#	ps listing sent via email + shutdown
		#	system knockdown, won't turn on without recovery.. 
		#	posix LSOF monitoring to watch for file handle references to filename... attack offenders
		#		^My favorite
		#	shutdown + boot to safemode + warning banner
		#	shutdown + startups reset + warning banner
		#	Crypto-library hunt (takes time, should be done via livecd)
		#	Boot to secondary OS, perform network backup
		
		#If email alerts have been enabled send an alert
		if self.conf['alerts_enabled']:
			msg = "Cryptolocked Alert.  A failsafe has been triggered\n\n"
			msg = msg + "system IP: " + self.get_IP() + "\n"
			if self.conf['sensitive_alerts']:
				msg = msg + "Host info: " + self.get_hostname() + "\n"
				msg = msg + "Process Data: " + self.get_processes() + "\n"
			self.send_alert(msg)
		

		#Simulated Action
                if not self.conf['armed_state'] or self.conf['only_arm_hunter']:
                        print "Trigger Simulated Failsafe"
                        allexit()

		if not self.conf['no_failsafe']:
			failsafe()

		allexit()


	def failsafe(self):
		#Catch all simple failsafe
		if os.name == "nt":
			os.system("shutdown -s -t 0")
		if os.name == "posix":
			os.system("shutdown -h now")
			
	def get_IP(self):
		if os.name == "nt":
			return os.popen('ipconfig').read()
		if os.name == "posix":
			return os.popen('ifconfig').read()
	
	def get_hostname(self):
		if os.name == "nt":
			return os.popen('nbtstat -n').read()
		if os.name == "posix":
			return os.popen('hostname').read()
			
	def get_processes(self):
		if os.name == "nt":
			return os.popen('tasklist').read()
		if os.name == "posix":
			return os.popen('ps aux').read()

	def check_loaded(self):
		return True
			
	#Initialization function
	#Creates the file
	def init(self, filename, content, hhash):
		print "Checking if tripfile " + filename + " exists:    ", ("File existed previously" if self.file_exists(filename) else False)
		if self.file_exists(filename):
			print "tripfile Destroyed"
			self.destroy_file(filename)
			print "tripfile Instantiated"
			self.create_file(filename, content, hhash)
			

def allexit():
	sys.exit(0)
			
#Main portion of the program
if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("-d","--debug", action="store_true", help="Enables debugging")
	parser.add_argument("-t","--tentacles", action="store_true", help="Enable tantacles feature")
	parser.add_argument("-a","--armed",action="store_true", help="Arm cryptolocked's countermeasures")
	parser.add_argument("-nf","--no-failsafe", action="store_true", help="Disable default failsafe countermeasure (use with --armed)")
	parser.add_argument("-nh","--no-hunter", action="store_true",help="Disable hunter countermeasure (use with --armed)")
	parser.add_argument("-oah","--only-arm-hunter", action="store_true", help='Only arm hunter')
	
	args = parser.parse_args()

	overrides = None

	if args.tentacles:
		overrides = {}
		overrides['tentacles'] = 'True'
	
	if args.armed:
		overrides = {}
		overrides['armed'] = 'True'

	if args.no_failsafe:
		overrides = {}
		overrides['no_failsafe'] = 'True'

	if args.no_hunter:
		overrides = {}
		overrides['no_hunter'] = 'True'

	if args.only_arm_hunter:
		overrides = {}
		overrides['only_arm_hunter'] = 'True'
		overrides['armed_state'] = 'False'

	cl = cryptolocked(overrides, debug=args.debug)

	signal.signal(signal.SIGINT, cl.safe_close)

	#if args.debug:
	#	cl.functionality_test()
	#else:
	#	if not cl.conf.no_hunter:
	#		h = hunter()
	#		t = threading.Thread(target=h.loop)
	#		t.daemon=True
	#		t.start()		
	#	if cl.conf['tentacles']:
	#		if t.loop():
	#			print cl.countermeasures()
	#

	
	while True:
		pass
