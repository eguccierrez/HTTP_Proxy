#!/usr/bin/env python

import sys
import socket
import threading
import thread
from threading import Thread
import select
import Queue
import os
from OpenSSL import crypto,SSL
import ssl
import subprocess
from subprocess import Popen, PIPE
import collections
from optparse import OptionParser

#Initialize hash counter
Id_cntr = collections.Counter()

# request = []

path = ''
r = 'r'
#Initialize Queue for use of threads
q = Queue.Queue()
#Initialize thread lock
threading_lock = threading.Lock()
# exit = 1
#set default timeout
timeout = None




# def explain():

# 	print '\npython proxy.py - [option]\n'
# 	print 'Options:\n'
# 	print '-h, --help\t\t\t\tdisplays information about executabe'
# 	print '-v, --version\t\t\t\tdisplays version of program and author'
# 	print '-p, --port [port number]\t\tport number that server will use'
# 	print '-n, --numworker [num_of_workers]\tSpecifies the number of workers in the thread pool used for handling concurrent HTTP requests (default:10)'
# 	print '-t, --timeout [timeout]\t\tThe time (seconds) to wait before give up waiting for response from server'
# 	print '-l, --log [log]\t\t\t\tLogs all the HTTP requests and their corresponding responses under the directory specified by log'

# 	print '\n'

#######################################################
###              INITIALIZE SOCKETS                 ###
###   1. Initializes thread pool                    ###
###   2. Socket API used to connect to client       ###
###   3. Read request from client                   ###
###   4. Input parameters into Queue                ###
#######################################################

def begin_connection(port_num,num_of_workers):

	for i in range(num_of_workers):
		worker = Thread(target=parse_request,args = (q,))
		worker.setDaemon(True)
		worker.start()

	try:
		server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		server_socket.bind(('',port_num))
		server_socket.listen(5)

	except Exception, e:
		print "~ Unable to initialize socket"
		sys.exit(2)

	while 1:

		try:
			(client_socket, address) = server_socket.accept()
			# print "~ Socket initialized"
			# print "~ Socket bound"
			# print ("~ Server started successfully [%d]\n" % (port_num))
			# print "~ Reading from socket..."
			recv_buffer = client_socket.recv(4096)
			# print "~ Received from client: ",recv_buffer, "\n"
			q.put((client_socket, recv_buffer, address))

		except KeyboardInterrupt:
			server_socket.close()
			print"\n~ Proxy Server Shutting Down..."
			sys.exit(1)
	server_socket.close()

#######################################################
###              WRITE INTO LOG FILE                ###
###   1. Add to hash counter                        ###
###   2. Check if path to logfile exists            ###
###   3. Write request and response into log file   ###
#######################################################

def logwrite(ip, servername,request,response):
	
	Id_cntr[servername] += 1
	idy = str(Id_cntr[servername])
	filename = "%s_%s_%s" % (idy,ip,servername)
	filename = filename+".txt"
	# print "In logfile, path is : ", path 
	completeName = os.path.join(path,filename)
	if not os.path.exists(os.path.dirname(completeName)):
		try:
			os.makedirs(os.path.dirname(completeName))
		except OSError as exc:
			print "~ No such directory or path. Please enter different log"
			print "~ Proxy Exiting..."
			os._exit(1)
			return

	with open(completeName,"w") as f:
		f.write("Request: %s \nResponce: %s" % (request, response))
		f.close()

########################################################
###              HTTPS CONNECTION                    ###
###  1. Sends OK back to client                      ###
###  2. Parse client reply, extract webserver/port   ###
###  3. Create certificate and key using openssl     ###
###  4. Get certificate from webserver               ###
###  5. Connect to webserver socket                  ###
###  6. Wrap socket using ssl with CA                ###
###  7. If ssl handshake fails, tunnel https traffic ###
########################################################
def https_proxy(client_socket,recv_buffer,address,first_line):

	reply = "HTTP/1.1 200 OK\r\n\r\n"
	client_socket.send(reply)
	temp = client_socket.recv(4096)
	print "Client replied: ", temp
	url = first_line.split(' ')[1]
	http = url.find("CONNECT")
	temp = url[(http+1):]
	port_y = temp.find(":")
	webserver_y = temp.find("/")

	if (webserver_y == -1):
			webserver_y = len(temp)
	webserver = ""
	port = -1
	if (port_y==-1 or webserver_y < port_y): #if there is no port number or if the port nuumber is after the webserver postion
		port = 80 #set a default port
		webserver = temp[:webserver_y]
	else:
		#use specific port 
		# print "temp[(port_y+1):] is "temp[(port_y+1):], "\n"
		port = int((temp[(port_y+1):])[:webserver_y-port_y-1])
		print port
		webserver = temp[:port_y]
		print "~ Port: ", port
		print "~ Webserver", webserver
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		# s.settimeout(timeout)
		s.connect((webserver,port))
		print "Connect..."
		print "Calling openssl, generating key"
		# process = subprocess.Popen(['openssl','genrsa','1024','>','server.key'], stdout=PIPE, stderr=PIPE)
		# stdout, stderr = process.communicate()
		# subprocess.call(['openssl','genrsa','1024','>','server.key'])
		# key = subprocess.check_output(['openssl','genrsa','1024','>','server.key'])
		# subprocess.call(['ls'])
		print "Output: \n", key
		subprocess.call(['ls'])
		cert = subprocess.check_output(['openssl','req','-x509','-newkey','rsa:2048','-keyout','key.pem','-out','cert.pem','-days','365','-nodes','-subj',"/C=US/ST=California/L=Goleta/O=CompanyName/OU=Org/CN=www.example.com"])
		print "Certificate: \n", cert
		subprocess.call(['ls'])
		y = open("cert.pem", "r")
		cert = y.read()
		y.close
		print "cert: \n",cert
		f = open("key.pem", "r")
		key = f.read()
		f.close()
		print "key: \n", key 
		google_cert = subprocess.check_output(['echo','|','openssl','s_client','-connect','google.com:443','2>/dev/null','|','openssl','x509'])
		print "google cert : \n", google_cert
		# subprocess.call(['ls'])
		# create_cert()
		# f = open(CERT_FILE)
		# cert_buffer = f.read()
		# f.close()
		# f = open(server.key)
		# key_buffer = f.read()
		# f.close()
		# from M2Crypto import RSA, X509 
		# cert = X509.load_cert_string(cert_buffer, X509.FORMAT_PEM) 
		# pub_key = cert.get_pubkey() 
		# rsa_key = pub_key.get_rsa() 
		# s = ssl.wrap_socket(s, cert_reqs=ssl.CERT_REQUIRED,ssl_version=ssl.PROTOCOL_TLS1,ca_certs='/home/enrique/Desktop/cs176b/')
		print "About to wrap socket"
		# s = ssl.wrap_socket(s, ciphers="ALL:aNULL:eNULL")
		s = ssl.wrap_socket(s, cert_reqs=ssl.CERT_REQUIRED,ca_certs='/home/enrique/Desktop/cs176b/')
		# s = ssl.wrap_socket(s,certfile = cert,keyfile=key, ssl_version=ssl.PROTOCOL_SSLv23)
		s.send(recv_buffer)
		reply = s.recv(9000)
		print "Reply is :",reply


		print "Socket has been wrapped\nAbout to get reply..."
		full = []
		# print "s.recv is:", s.recv(4096)
		while 1:
			print '~ HTTPS while loop'
			s.setblocking(0)
			ready = select.select([s],[],[],5)
			if ready[0]:
				reply = s.recv(4096)
				print "~ Reply is: ", reply
				if (len(reply) > 0):
					full.append(reply)
				else:
					break
			else:
				break

			full_reply = ''.join(full)
			logwrite(str(idr),str(address[0]),str(webserver),str(recv_buffer), full_reply)
			idr = idr + 1
			# print "~ Reply Received: ", "\n", full_reply, "\n"

			if (len(full_reply) > 0): #send reply back to client
				client_socket.send(full_reply)
				#send notification to proxy server
				print "~ Request Done: %s" % (str(address[0]))
			else:
				print "~ Length of reply is zero"

			s.close()
			client_socket.close()
	except socket.error, (value, message):
			s.close()
			client_socket.close()
			sys.exit(1)

##########################################################
###              PARSE REQUEST                         ###
### 1. Get queue content into their respective vars    ###
### 2. Determine kind of request (GET,CONNECT,POST)    ###
### 3. Call function to initialize connction w webserver##
##########################################################

def parse_request(q):

	while True:
		client_socket,recv_buffer,address = q.get()
		try:
			wut = recv_buffer
			# print "~ In parse_request function ..."
			if (len(wut) < 0):
				print "request from client is empty"
				pass
			line = recv_buffer.split('\n')[0] #grab the first line in the buffer
			if ("GET" not in line):
				print "~ HTTPS Request"
				# print "POST OR CONNECT", recv_buffer[0]
				pass
				# https_proxy(client_socket,recv_buffer,address,line)
				# print "HTTPS CONNECT contains: ",recv_buffer
				# print "\nFirst line: ", line 
			else:
				print "~GET request"
				# print "~ First line contains: ", line
				#Grab URL from line
				url = line.split(' ')[1]
				http = url.find("://") #find the begginning of the url
				if (http == -1): #if it cant find it 
					temp = url #grab the whole url
				else:
					#otherwise
					temp = url[(http+3):] #Get what follows after :// aka the full url
				port_x = temp.find(":") #find the position of the port within the url
				webserver_x = temp.find("/") #Find the end of the webserver

				if (webserver_x == -1):
					webserver_x = len(temp)
				webserver = ""
				port = -1
				if (port_x==-1 or webserver_x < port_x): #if there is no port number or if the port nuumber is after the webserver postion
					port = 80 #set a default port
					webserver = temp[:webserver_x]
				else:
					#use specific port 
					port = int((temp[(port_x+1):])[:webserver_x-port_x-1])
					webserver = temp[:port_x]

				# print "~ About to call proxy_server function ..."
				proxy_server(webserver, port, client_socket, address, recv_buffer)
		
		except Exception, e:
			print "~ Unexpected Error:", sys.exc_info()[0]
			raise

#######################################################
###              PROXY SERVER CONNECTION            ###
###  1. Initialize connection with webserver        ###
###  2. Set proper timeout value                    ###
###  3. Send client's request forward               ###
###  4. Read reply from server                      ###
###  5. If logfile available then call Logwrite     ###
###  6. Send reply back to client                   ###
###  7. Close connection                            ###
#######################################################    

def proxy_server(webserver, port, client_socket, address, recv_buffer):

	try:
		# print "~ In proxy server function ..."
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(timeout)
		s.connect((webserver,port))
		s.send(recv_buffer)
		full = []
		while 1:
			# print '~ In while loop'
			s.setblocking(0)
			ready = select.select([s],[],[],1)
			if ready[0]:
				reply = s.recv(4096)

				if (len(reply) > 0):
					full.append(reply)
				else:
					break
			else:
				break

		full_reply = ''.join(full)

		if path != '':
			threading_lock.acquire(True)

			logwrite(str(address[0]),str(webserver),str(recv_buffer), full_reply)

			threading_lock.release()

		if (len(full_reply) > 0): 
		#send reply back to client
			client_socket.send(full_reply)
			#send notification to proxy server
			print "~ Request Done: %s" % (str(address[0]))
		else:
			# print "~ Length of reply is zero"
			pass

		s.close()
		client_socket.close()
	except socket.error, (value, message):
		s.close()
		client_socket.close()
		sys.exit(1)

#######################################################
###              INPUT PARSING                      ###
#######################################################

def input_parsing():
	explain = "usage: mproxy.py -p [port]"
	parser = OptionParser(usage=explain)
	parser.add_option("-v","--version",help="Displays version of program and author",action="store_true",dest="version")
	parser.add_option("-p","--port",help="Port number that server will use'",action="store",dest="port", type="int")
	parser.add_option("-n","--numworker",help="Specifies the number of workers in the thread pool used for handling concurrent HTTP requests (default:10)",action="store",dest="num_of_workers",default =10,type="int")
	parser.add_option("-t","--timeout",help="The time (seconds) to wait before give up waiting for response from server",action="store",dest="timeout",default=None,type="int")
	parser.add_option("-l","--log",help="Logs all the HTTP requests and their corresponding responses under the directory specified by log",action="store",dest="path",type="string")
	(results,args) = parser.parse_args()

	if results.version == True:
		print "\nmproxy.py,0.1,Enrique Gutierrez\n"
		sys.exit(0)
	if results.port == None:
		parser.error("No port specified")
		# sys.exit(0)

	return (results, args)
	

#######################################################
###              MAIN FUNCTION                      ###
### 1.Parses user input using optparse.OptionParser ###
### 2.Calls function to initialize sockets          ### 
#######################################################

def main(argv):
	global path 
	(opts,args) = input_parsing()
	timeout = opts.timeout
	path = opts.path
	begin_connection(opts.port,opts.num_of_workers)

'''Parsing with OPT ARG doesn't handle required arguments from user input'''
 # 	try:
 # 		opts, args = getopt.getopt(argv, "hvt:p:l:n:",["port=","version","help","log=","numworker=","timeout="])
 # 	except getopt.GetoptError:
 # 		print '~ InputError: run python pproxy.py -h for help'
 # 		print "here"
 # 	print "sup"
 # 	for opt,arg in opts:
 # 		if opt in ("-h","--help"):
 # 			explain()
 # 			return 0
 # 		elif opt in ("-v","--version"):
 # 			print '\nmproxy.py,0.1,Enrique Gutierrez\n'
 # 			return 0
 # 		elif opt in ("-p","--port"):
 # 			port_num = int(arg)
 # 		elif opt in ("-n","--numworker"):
 # 			num_of_workers = int(arg)
 # 		elif opt in ("-t","--timeout"):
 # 			timeout = int(arg)
 # 		elif opt in ("-l","--log"):
 # 			if arg == None:
 # 				print "yeeee"
 # 			path = arg
 # 			print "path is:", path , "\n"
	# print " dkjsd"
 # 	begin_connection(port_num,num_of_workers)

if __name__ == "__main__":
	main(sys.argv[1:])


