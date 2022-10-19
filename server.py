'''************************************************
Title: AP3PAAPUAPID Server
Author: Nobodit Choudhury
Date: 05-09-2022
************************************************'''
import socket
import random
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

SID="SID123456789"
clen = int(5)
nlen = int(6)
idlen = int(12)
key="w9z$C&E)H@McQfTj"

def write_file(uid,sigma):
    #add check if uid does not exist in file
    with open('py_data.txt', 'a') as f:
        f.write(sigma)
        f.write('\n')
    f.close()

def retrieve_sigma(uid):
    #print("at read: ", uid) 
    #retrieve uid entry from file
    #sigma = uid,c,n,alpha
    f = open("py_data.txt", "r")
    for x in f:
    #print(x,end="")
        #print("at read: ", x[:idlen]) 
        if(uid == x[:idlen]):
            break
    #print(x[x.find("C"):x.find("C")+5],x[x.find("N"):x.find("N")+6],x[x.rfind("#")+1:])
    C=x[x.find("C"):x.find("C")+5]
    seed=x[x.find("S"):x.find("S")+6]
    alpha = x[x.rfind(",")+1:]
    alpha = alpha.strip()
    #print("at read c,seed,alpha: ",C,seed,alpha)
    f.close()
    return (C,seed,alpha)

def enrollment(conn, uid):
    #print("\nAt enroll:")
    ret =0
    #create Challenge,seed
    C="C"+str(random.randint(1000,9999))
    seed="S"+str(random.randint(10000,99999))
    #print("c, s: ",C,seed)
    cs = C+seed
    #print("cs: ",cs)
    cs = AESCipher(key).encrypt(cs).decode('utf-8') #encrypted challenge and nonce
    #print("cs: ",cs)
    #send cs
    conn.send(cs.encode())
    #rcv eac
    eac = conn.recv(1024).decode()
    #print("eac: ",eac)
    #decrypt eac
    eac = AESCipher(key).decrypt(eac).decode('utf-8')
    #print("eac: ",eac)
    #alpha, client_C = eac[:clen], eac[clen:]
    alpha, client_C = eac[:len(eac)-clen], eac[len(eac)-clen:]
    #print("alpha, clientc: ",alpha, client_C)
    if( client_C == C):
        #sendack
        conn.send("1".encode())
        ret=1
        #prepare sigma = uid,c,seed,alpha\n and store in file
        sigma = uid+","+C+","+seed+","+str(alpha)
        write_file(uid,sigma)
    return ret    
    
def authenticate(conn, uid):
    #print("\nAt auth:")
    ret = 0
    #retrieve uid entry from file
    #c seed alpha
    C,seed,alpha = retrieve_sigma(uid)
    #print(C,seed,alpha)
    N="N"+str(random.randint(10000,99999))
    #print("nonce:",N)
    
    #send C,nonce,seed
    cns = C+N+seed
    #print("cns: " + cns)
    #send c,nonce,seed #c,n,sid,n2 ******sid known to client previously **************also put reauthenticate logic
    conn.send(cns.encode())
    
    beta = hashlib.sha256((alpha+N).encode()).hexdigest()
    #rcv beta client
    client_beta = conn.recv(1024).decode()
    #print("beta generated: " + str(beta))
    #print("beta from user: " + str(client_beta))
    #send ack
    if(client_beta == beta):
        ret = 1
        conn.send("1".encode()) 
        
    else:
        conn.send("0".encode())
    return ret

def server_program():
    
    try:
        print("At server:")
        # get the hostname
        host = socket.gethostname()
        port = 5000  # initiate port no above 1024

        server_socket = socket.socket()  # get instance
        # look closely. The bind() function takes tuple as argument
        server_socket.bind((host, port))  # bind host address and port together

        # configure how many client the server can listen simultaneously
        server_socket.listen(2)
        conn, address = server_socket.accept()  # accept new connection
        print("Connection from: " + str(address))
        
        #rcv data
        data = conn.recv(1024).decode()
        #print("from connected user: " + str(data))
        uid = str(data)
        if( uid[:3] == "UID"):
            enrollment(conn, uid)
        
        auth = 0
        #rcv data
        data = conn.recv(1024).decode()
        #print("from connected user: " + str(data))
        uid = data
        if( uid[:3] == "UID"):
            auth=authenticate(conn, uid)
        
        print("auth status:", auth)
        #if(auth)
            
        '''
        #rcv data
        data = conn.recv(1024).decode()
        print("from connected user: " + str(data))
        
        key="nobodit"
        #send data
        data = input(' -> ')
        #aes128 = AESCipher(key)
        ctext = AESCipher(key).encrypt(data).decode('utf-8')
        print('Ciphertext:', ctext)#AESCipher(pwd).encrypt(msg).decode('utf-8')
        conn.send(ctext.encode()) 
        '''
        
        if(auth):
            #rcv data
            #data = conn.recv(1024).decode()
            #print("from connected user: " + str(data))
            while True:
                # receive data stream. it won't accept data packet greater than 1024 bytes
                data = conn.recv(1024).decode()
                if not data:
                    # if data is not received break
                    break
                print("from connected user: " + str(data))
                data = input(' -> ')
                conn.send(data.encode())  # send data to the client
        
        conn.close()  # close the connection
    except:
        print("authentication failed")

if __name__ == '__main__':
    server_program()