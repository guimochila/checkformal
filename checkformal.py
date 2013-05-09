#!/usr/bin/python
#
# Script to verify the file in virustotal.
# Automating the basic static malware analysis.
# Coded by Guilherme
#
# check_mal  - A tool to use to automate malware analysis. It check all files against virustotal database.
#
#
# Responses: 0 - Not found in database
#			-2 - Still queded for querying
#			 1 - It was found in database and response was received.
#
# Possible errors: HTTP 204 - Exceed API request limit
#                  HTTP 403 - Do not have permission
#
# Virustotal URLs:
#       Send & Scanning file - https://www.virustotal.com/vtapi/v2/file/scan
#		Rescanning submitted files - https://www.virustotal.com/vtapi/v2/file/rescan
#		Retrieving Report - https://www.virustotal.com/vtapi/v2/file/report
#		Send & Scanning URL - https://www.virustotal.com/vtapi/v2/url/scan
#		Retrieving URL report - http://www.virustotal.com/vtapi/v2/url/report
#		Retrieving IP Address - http://www.virustotal.com/vtapi/v2/ip-address/report
#		Retrieving Domain Report - http://www.virustotal.com/vtapi/v2/domain/report
#

import sys
import os
import argparse
import json
import urllib
import urllib2
import hashlib
import subprocess
import re
import peutils
import pefile
import zipfile
import datetime

#Here you have to put your own API key from VirusTotal
vt_api_key=""

url = "https://www.virustotal.com/vtapi/v2/"

url_mode = {'scan': 'file/scan',
			'rescan': 'file/rescan',
			'freport' : 'file/report',
			'uscan': 'url/scan',
			'ureport': 'url/report',
			'ipreport': 'ip-address/report',
			'domain': 'domain/report'}


class WReporter:

	def __init__(self, stdout, fname):
		self.stdout = stdout
		self.logfile = file(fname,'a')

	def write(self, line):
		self.stdout.write(line)
		self.logfile.write(line)

	def close(self):
		self.stdout.close()
		self.logfile.close()

def init_report(target):

	date =  datetime.datetime.now()
	report_name = md5sum + '/report_' + date.strftime('%Y-%m%d_%H:%M:%S') + '.txt'
	f = open(report_name, 'w')
	f.write('[+] Analysis date: %s\n' %  date.strftime('%Y-%m%d_%H:%M:%S'))
	f.write('[+] File name: %s\n' % os.path.basename(target))
	f.write('[+] MD5: %s\n' % md5sum)
	f.close()
	reporter = WReporter(sys.stdout, report_name)
	sys.stdout = reporter


def compress(target):

	dst = md5sum + '/' + os.path.basename(target) + '.zip'

	with zipfile.ZipFile(dst,'w') as zp:
		zp.write(target)

	return

def vt_check(target, md5):

	print "[+] Checking VirusTotal database..."

	parameters = {"resource": md5, "apikey": vt_api_key }
	data = urllib.urlencode(parameters)
	req =  urllib2.Request(url+url_mode['freport'], data)
	response = urllib2.urlopen(req)
	
	j = json.loads(response.read())

	if j['response_code'] == 0:
		print "[!] Not found in the VirusTotal database. "
		return

	print "[+] Detection rate: %s / %s " % (j['positives'], j['total'])

	for av in j['scans']:
		if j['scans'][av]['detected'] == True:
			print "  [>]%s : \t%s" % (av, j['scans'][av].get('result'))
		
		
	
#Function that call strings, for get all strings from the file
#Call the native strings's command from the OS, for windows it should be necessary to install
#the strings command from the Sysinternal suite tools from Microsoft.
def call_strings(target):
	
	print "[+] Trying to catch some possible Domain/URL/IP/Email from Strings: "

	try:
		p = subprocess.Popen(["strings", target], stdout=subprocess.PIPE)
		p_output = p.stdout.read()
	except subprocess.CalledProcessError, e:
		print "Error: " + e.output



	#Try to find URLs inside the strings
	url_patterns = {r'http*?://[^\s]+',
					r'[\w\-][\w\-\.]+@[\w\-][\w\-\.]+[a-zA-Z]{1,4}',
					r'[0-9A-Za-z]+(?:\.[0-9A-Za-z]+){3}[^\s]+',
					r'[0-9]+(?:\.[0-9]+){3}[^\s]+',										
					}

	ms = 0
	for pattern in url_patterns:				
		matches = re.findall(pattern, p_output)
		if matches:
			ms = 1
			for found in matches:
				print '[!]--> %s' % found
				
	if ms == 0:
		print "[!]--> No matched strings found =(. Obfuscated?!"

 	return

#Function that calculates the md5 hash from a file, useful to search on virustotal website as a first method,
#instead of upload the file again.
def md5_ini(target):

	try:
		md5 = hashlib.md5()
		with open(target, 'rb') as f:
			for buf in iter(lambda: f.read(128), b''):
				md5.update(buf)
	except:
		print "[!] Warning: It was not possible to calculate the MD5"
		return 
		
	
	global md5sum 
	md5sum = md5.hexdigest()
	
	print "[+] MD5: %s" % md5sum

	return 

def identify_packer(target):

	pe = pefile.PE(target)
	packer_id = peutils.SignatureDatabase('userdb.txt')
	match_packer = packer_id.match(pe, ep_only=True)

	if not match_packer:
		print "[!] Packers info: Packer not found or not recognized"
	else:
		print "[+] Packers info: %s" % match_packer

	return

#Main function responsable to call the parse the arguments and call others functions
def main():

	desc = "check_mal v0.1 - Tool for automate malware analysis. By smurfx80[at]gmail[dot]com"

	parser = argparse.ArgumentParser(description = desc)
	parser.add_argument('-f', dest='f_name', help="Use for a single file analysis")
	
	args = parser.parse_args()

	if len(sys.argv) <= 1:
		print parser.print_help()
		sys.exit(-1)

	if not args.f_name:
		print parser.print_help()
		sys.exit(-1)

	target = args.f_name

	if not os.path.isfile(target):
		print "[-] Error: File %s not found or is not a valid file." % target
		sys.exit(0)
	


	print "[+] File name: %s " % os.path.basename(target)

	md5_ini(target)
	#Identify the packer

	if not os.path.exists(md5sum):
		os.makedirs(md5sum)

	init_report(target)

	#Try to identify the packer
	identify_packer(target)
	#Check for strings
	call_strings(target)
	#Virus Total Check
	vt_check(target, md5sum)
	#compress - final stage
	compress(target)

if __name__ == "__main__":
	main()
