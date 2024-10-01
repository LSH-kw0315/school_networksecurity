import socket
import sys

def port_scanner(target_ip, start_portno, end_portno):
	for port_number in range(start_portno, end_portno):
        	#TODO: your code here
		s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		#s.settimeout(1)
		try:
            	#TODO: your code here
			result=s.connect_ex((target_ip,port_number))
			s.close()
			#s.sendto(b'',(target_ip,port_number))
			#print(f"result:{result}")
			#s.recvfrom(1024)
			#print(f"open port:{port_number}")
			if result==0:
				print(f"open port:{port_number}")
		except ConnectionRefusedError:
			continue
		except TimeoutError:
			continue
		finally:
			s.close()
	
if __name__ == '__main__':
        
	target_ip = sys.argv[1]
	start_portno = int(sys.argv[2])
	end_portno = int(sys.argv[3])

	port_scanner(target_ip, start_portno, end_portno)
