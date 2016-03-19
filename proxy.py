#!/usr/bin/env python

import sys, getopt
import socket
import thread


def explain():
	print '\npython proxy.py - [option]\n'
	print 'Options:\n'
	print '-h, --help\t\t\t\tdisplays information about executabe'
	print '-v, --version\t\t\t\tdisplays version of program and author'
	print '-p, --port [port number]\t\tport number that server will use'
	print '-n, --numworker [num_of_workers]\tSpecifies the number of workers in the thread pool used for handling concurrent HTTP requests (default:10)'
	print '-t, --timeout [timeout]\t\tThe time (seconds) to wait before give up waiting for response from server'
	print '-l, --log [log]\t\t\t\tLogs all the HTTP requests and their corresponding responses under the directory specified by log'

	print '\n'

def begin_connection(port_num,num_of_workers):
	try:
		server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		#server_socket.bind(('127.0.0.1',80))
		server_socket.bind(('',port_num))
		server_socket.listen(5)
	except Exception, e:
		print "~ Unable to initialize socket"
		sys.exit(2)

	while 1:
		try:
			(client_socket, address) = server_socket.accept()
			print "~ Socket initialized"
			print "~ Socket bound"
			print ("~ Server started successfully [%d]\n" % (port_num))
			print "~ Reading from socket..."
			recv_buffer = client_socket.recv(1024)
			if logfile != "n":

				logfile.write(recv_buffer)
				logfile.write('\n')
			print "~ Received from client: ",recv_buffer, "\n"
			print "~ Starting new thread for request..."
			# for i in range(num_of_workers):
			# 	Thread_ID = i
			# 	print "~ Thread ID: ", Thread_ID
			# 	thread.start_new_thread(parse_request, (client_socket, recv_buffer, address))

			thread.start_new_thread(parse_request, (client_socket, recv_buffer, address))

		except KeyboardInterrupt:
			server_socket.close()
			print"\n~ Proxy Server Shutting Down..."
			sys.exit(1)

	server_socket.close()

def parse_request(client_socket,recv_buffer,address):
	try:
		print "~ In parse_request function ..."
		#print "[*] recv_buffer contains: ",recv_buffer
		first_line = recv_buffer.split('\n')[0] #grab the first line in the buffer
		print "~ First line contains: ", first_line
		url = first_line.split(' ')[1]
		# print "poop"
		http = url.find("://") #find the begginning of the url
		#print "[*] Here 1"
		if (http == -1): #if it cant find it 
			temp = url
		else:
			temp = url[(http+3):] #Get what follows after :// aka the full url
		# print "[*] Here 2"
		port_pos = temp.find(":") #find the position of the port within the url
		webserver_pos = temp.find("/") #Find the end of the webserver

		if (webserver_pos == -1):
			webserver_pos = len(temp)
		webserver = ""
		port = -1
		# print "[*] Here 3"
		if (port_pos==-1 or webserver_pos < port_pos): #if there is no port unmber or if the port nuumber is after the webserver postion
			port = 80 #set a default port
			webserver = temp[:webserver_pos]
		else:
			#use specific port 
			port = int((temp[(port_pos+1):])[:webserver_pos-port_pos-1])
			webserver = temp[:port_pos]

		print "~ About to call proxy_server function ..."
		proxy_server(webserver, port, client_socket, address, recv_buffer)
	except Exception, e:
		print "~ Unexpected Error:", sys.exc_info()[0]
		raise

def proxy_server(webserver, port, client_socket, address, recv_buffer):
	try:
		print "~ In proxy server function ..."
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((webserver,port))
		s.send(recv_buffer)

		#Read the reply
		reply = s.recv(1024)
		if logfile != "n":
			logfile.write(reply)
			logfile.write('\n')
		print "~ Reply Received: ", reply, "\n"
		# reply = s.recv(1024)
		# print "~ Reply Received: ", reply, "\n"

		if (len(reply) > 0): #send reply back to client
			client_socket.send(reply)
			#send notification to proxy server
			dar = float(len(reply))
			dar = float(dar / 1024)
			dar = "%.3s" % (str(dar))
			dar = "%s KB" % (dar)
			print "~ Request Done: %s => %s <=" % (str(address[0]), str(dar))
		else:
			print "~ Length of reply is zero"

		s.close()
		client_socket.close()
	except socket.error, (value, message):
		s.close()
		client_socket.close()
		sys.exit(1)

def main(argv):

	logfile = "n"
	port_num = 8888
	num_of_workers = "0"

 	try:
 		opts, args = getopt.getopt(argv, "hvp:l:n:",["port=","version","help","log=","numworker="])
 	except getopt.GetoptError:
 		print '~ InputError: run python proxy.py -h for help'

 	for opt,arg in opts:
 		if opt in ("-h","--help"):
 			explain()
 			return 0
 		elif opt in ("-v","--version"):
 			print '\nmproxy.py,0.1,Enrique Gutierrez\n'
 			return 0
 		elif opt in ("-p","--port"):
 			port_num = int(arg)
 		elif opt in ("-n","--numworker"):
 			num_of_workers = int(arg)
 		elif opt in ("-t","--timeout"):
 			timeout = int(arg)
 		elif opt in ("-l","--log"):
 			global logfile
 			logfile = arg
 			logfile = open(logfile,'w')

 	begin_connection(port_num,num_of_workers)
 	print '~ About to close logfile'
 	logfile.close()
 	print '~ Logfile closed'

if __name__ == "__main__":
	main(sys.argv[1:])


