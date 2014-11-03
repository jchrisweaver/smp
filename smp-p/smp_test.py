#!/usr/bin/env python

# Original code is from Shane Tully's "MITM Protection via the Socialist Millionaire Protocol (OTR-style)"
# https://shanetully.com/2013/08/mitm-protection-via-the-socialist-millionaire-protocol-otr-style/

import smp
import socket
import sys
import M2Crypto

from smp import longToBytes
from smp import padBytes

# Check command line args
if len(sys.argv) != 2:
    print "Usage: %s [IP/listen]" % sys.argv[0]
    sys.exit(1)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

if sys.argv[1] == 'listen':
    # Listen for incoming connections
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', 5000))
    sock.listen(1)
    print "Listening for client"
    client = sock.accept()[0]

    # Prompt the user for a shared secret to use in SMP
    secret = raw_input("Enter shared secret: ")

    # Create an SMP object with the calculated secret
    smp = smp.SMP(secret)

    # Do the SMP protocol
    buffer = client.recv(4096)[ 4:]

    buffer = smp.step2(buffer)
    tempBuffer = padBytes( longToBytes( len( buffer ) + 4 ), 4 ) + buffer
    client.send( tempBuffer )
    
    buffer = client.recv(4096)[ 4:]
    
    buffer = smp.step4(buffer)
    tempBuffer = padBytes( longToBytes( len( buffer ) + 4 ), 4 ) + buffer
    client.send( tempBuffer )
        
else:
    # Connect to the server
    sock.connect((sys.argv[1], 5000))

    # Prompt the user for a shared secret to use in SMP
    secret = raw_input("Enter shared secret: ")

    # Create an SMP object with the calculated secret
    smp = smp.SMP(secret)

    # Do the SMP protocol
    buffer = smp.step1()
    tempBuffer = padBytes( longToBytes( len( buffer ) + 4 ), 4 ) + buffer
    sock.send( tempBuffer )

    buffer = sock.recv(4096)[4:]
    buffer = smp.step3(buffer)
    tempBuffer = padBytes( longToBytes( len( buffer ) + 4 ), 4 ) + buffer
    sock.send( tempBuffer )

    buffer = sock.recv(4096)[4:]
    smp.step5(buffer)

# Check if the secrets match
if smp.match:
    print "Secrets match"
else:
    print "Secrets do not match"
