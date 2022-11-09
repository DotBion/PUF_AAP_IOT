'''************************************************
Title: AP3PAAPUAPID Client
Author: Nobodit Choudhury
Date: 05-09-2022
************************************************'''
import socket
import hashlib
from hashlib import md5
from base64 import b64decode
from base64 import b64encode

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class AESCipher:
    def __init__(self, key):
        self.key = md5(key.encode('utf8')).digest()

    def encrypt(self, data):
        iv = get_random_bytes(AES.block_size)
        self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + self.cipher.encrypt(pad(data.encode('utf-8'), 
            AES.block_size)))

    def decrypt(self, data):
        raw = b64decode(data)
        self.cipher = AES.new(self.key, AES.MODE_CBC, raw[:AES.block_size])
        return unpad(self.cipher.decrypt(raw[AES.block_size:]), AES.block_size)

UID = "UID123456789"
clen = int(5)
nlen = slen = int(6)
idlen = int(12)
key="w9z$C&E)H@McQfTj"
# nb key="w1z$C&E)H@McQfTj"

#protocol assumes sid is known
SID = "SID123456789"

def enrollment(client_socket):
    ret = 0
    #print("\nAt enroll:")
    #send UID to enroll
    message = UID  # take input
    client_socket.send(message.encode())  # send message
    #receive encrypted C,Seed
    cs = client_socket.recv(1024).decode()  
    #print('Received from server: ' + cs)
    #decrypt c,seed
    cs = AESCipher(key).decrypt(cs).decode('utf-8')
    #********************,sid??    , data[clen+nlen:] and rename nonce to seed
    C,seed = cs[:clen], cs[clen:]
    #print('C, seed: ', C,seed)
    rpuf = hashlib.sha256(C.encode()).hexdigest()#to be replaced by puf implementation
    #print("rpuf: ",rpuf)
    alpha = hashlib.sha256((rpuf+seed+SID).encode()).hexdigest()
    #print("alpha: ",alpha)
    #encrypt alpha and C and send
    eac = alpha+C
    #print("eac: ",eac)
    eac = AESCipher(key).encrypt(eac).decode('utf-8')
    #print("eac: ",eac)
    #send eac
    client_socket.send(eac.encode()) 
    #rcv ack
    data = int(client_socket.recv(1024).decode())
    if(data == 1):
        ret = 1
    return ret

def authenticate(client_socket):
    print("\nAt auth:")
    #UID = "UID123826789"
    #send UID to authenticate ************************************tobe used only for client initiated auth request #reauthenticate request should directly execute
    message = UID 
    client_socket.send(message.encode()) 
    
    #rcv c,n,seed               #sid,n2
    ecns = client_socket.recv(1024).decode()  
    print('Received from server: ' + ecns)
    ecns = str(ecns)
    print('Received from server: ' + ecns)
    
    ids_score = int(ecns[0])
    print('ids_score: ', ids_score)
    ecns = ecns[1:]
    print('trim cns: ' + ecns)
    
    if(ids_score):
        cns = AESCipher(key).decrypt(ecns).decode('utf-8')
        C,N,seed = cns[:clen], cns[clen:clen+nlen], cns[clen+nlen:]
        #print('C, nonce, seed: ', C,N,seed)
        rpuf = hashlib.sha256(C.encode()).hexdigest()
        #print("rpuf: ",rpuf)
        alpha = hashlib.sha256((rpuf+seed+SID).encode()).hexdigest()
        #print("alpha: ",alpha)
        beta = hashlib.sha256((alpha+N).encode()).hexdigest()
        eb = AESCipher(key).encrypt(beta).decode('utf-8')
        #print("alpha+N2: ",alpha+N)
        #send encrypted beta
        client_socket.send(eb.encode()) 
    else:
        cns = ecns
        C,N,seed = cns[:clen], cns[clen:clen+nlen], cns[clen+nlen:]
        #print('C, nonce, seed: ', C,N,seed)
        rpuf = hashlib.sha256(C.encode()).hexdigest()
        #print("rpuf: ",rpuf)
        alpha = hashlib.sha256((rpuf+seed+SID).encode()).hexdigest()
        #print("alpha: ",alpha)
        beta = hashlib.sha256((alpha+N).encode()).hexdigest()
        #print("alpha+N2: ",alpha+N)
        #send beta
        client_socket.send(beta.encode()) 
    #rcv ack
    data = int(client_socket.recv(1024).decode())
    return data
    

def client_program():
    #try:
        print("At client_program:")
        host = socket.gethostname()  # as both code is running on same pc
        port = 5000  # socket server port number

        client_socket = socket.socket()  # instantiate
        client_socket.connect((host, port))  # connect to the server
        
        enroll=0
        auth = 0
        if enroll==0:
            enroll = enrollment(client_socket)
        
        auth = authenticate(client_socket)
        print("auth status:",auth)
        '''
        #send data
        message = input(" -> ")  # take input
        client_socket.send(message.encode())  # send message
        
        key="nobodit"
        #rcv data
        data = client_socket.recv(1024).decode()  # receive response
        print('Received from server: ' + data)
        #aes128 = AESCipher(key)
        ptext = AESCipher(key).decrypt(data).decode('utf-8')
        print('plaintext:', ptext)
        '''
        
        if(auth):
            #send data
            message = input(" -> ")  # take input
            #client_socket.send(message.encode())  # send message
            while message.lower().strip() != 'bye':
                client_socket.send(message.encode())  # send message
                data = client_socket.recv(1024).decode()  # receive response

                print('Received from server: ' + data)  # show in terminal

                message = input(" -> ")  # again take input
        
        client_socket.close()  # close the connection
    #except:
    #    print("authentication failed")
    

if __name__ == '__main__':
    client_program()
