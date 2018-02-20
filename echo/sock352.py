
# This is the skeleton code of a cs 352 socket
# You must change the code in the pass statements to make the client and server work. 

import socket as ip

class socket:

    def __init__(self):
        self.socket = ip.socket(ip.AF_INET, ip.SOCK_DGRAM);
    
    def socket():
    	pass
    
    def bind(self,address):
    	self.socket.bind(address);
        
    def sendto(self,buffer,address):
        self.socket.sendto(buffer, address);

    def recvfrom(self,nbytes):
    	return self.socket.recvfrom(nbytes);

    def close(self):
        self.socket.close();


