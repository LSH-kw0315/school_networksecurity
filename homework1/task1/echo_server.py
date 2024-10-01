import socket

IP = '127.0.0.1'
PORT = 9999
BUF_SIZE = 4096

#TODO: make a server-socket
server=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#TODO: bind the IP, port number to the server-socket
server.bind((IP, PORT))
#TODO: make the socket a listening state
server.listen()
client, addr = server.accept()
print(f"Connected from {addr}")

try:
	while True:
		response = client.recv(BUF_SIZE)
		if not response: break
		#TODO: send the response back to the client
		buf=response.decode()
		client.send(response)
		print(buf)
except:
    client.close()
    server.close()

