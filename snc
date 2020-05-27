#!/usr/bin/env python3

import argparse
import logging
import socket
import sys
from Crypto.Protocol.KDF import PBKDF2
from base64 import b64encode
from Crypto.Random import get_random_bytes
import json
from base64 import b64decode
from Crypto.Cipher import AES
import os


def server():
    logging.debug('entered in server mode')
    port=args.port
    logging.debug('the port to open is ' + port)
    #the above lines give us the port number we need to open

    ServerSocket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    ServerSocket.bind(('',int(port)))
    ServerSocket.listen(1)
    logging.debug('the server is now listening')
    #the server has now started listening on the port number specified above in arguments

    ClientSocket, ClientAddress = ServerSocket.accept()
    logging.debug(f"connection from {ClientAddress} has been established")
    #the server has established a connection with the client


    #we will read the data on chunks ( of size 4197 ) from the buffer of socket
    READ_BUFFER = 4197
    while True:
        content = ClientSocket.recv(READ_BUFFER)
        if content==b'':            #condition to check if the buffer is empty or EOF has been reached
            break

        logging.debug("the size of content received is " + str(sys.getsizeof(content)))
        content_decoded=content.decode('utf-8') #decoding the chunk data in utf-8 format
        decrypt(content_decoded)                #passing that chunk of data to the decrypt function

    ServerSocket.close()
    pass


def client():
    logging.debug('entered in client mode')
    input_key=args.key
    server_address = args.ip_address
    port = args.port
    logging.debug('the server and port to open connection to is ' + server_address + " " + port)
    #now the client knows what ip address and port to connect to

    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientSocket.connect((server_address, int(args.port)))
    #client is now connecting to the server
    FILE_READ_BUFFER=3000
    #file_read_buffer is te amount of bytes in the chunk , that the server will read
    #and encrypt at one point of time

    while True:
        salt = get_random_bytes(30) #generating salt value
        logging.debug("salt is +" + str(salt)) #debug statement ( please ignore )
        crypto_key = PBKDF2(input_key, salt, 16) #calling pbkf2 to generate key , that will be used for encrytpion
        logging.debug('cryptokey is ' + str(crypto_key)) #debug statement ( please ignore )

        chunk = sys.stdin.buffer.read(FILE_READ_BUFFER) #reading a chunk of data from STDIN
        header = b"header"
        data = chunk
        cipher = AES.new(crypto_key, AES.MODE_GCM)  #creating a new cipher insatnce
        cipher.update(header)
        ciphertext, tag = cipher.encrypt_and_digest(data) # creating a cipher text and tag associated with it


        json_k = ['nonce', 'header', 'ciphertext', 'tag','salt']
        json_v = [b64encode(x).decode('utf-8') for x in (cipher.nonce, header, ciphertext, tag, salt)]
        result = json.dumps(dict(zip(json_k, json_v)))
        #the above 3 lines do the following:
        #create a json object , with the key pair as nonce , header , ciphertext , tag , and salt
        #add the correspoing value to it
        #SALT is now a part of json object that we will sed over. The server will extract this salt, and will use it further for decryption


        binary_data = result.encode('utf-8') #converting the object, such that it can be sent over socket
        logging.debug ("size of binary data  "+ str(sys.getsizeof(binary_data) )) #debug statement , please ignore
        clientSocket.send(binary_data)

        if len(chunk)!=FILE_READ_BUFFER:
            break


    clientSocket.close()
    logging.debug("socket will be closed now") #debug statement , please ignore
    pass

#the beginning of decryption function
def decrypt(content_decoded):

    logging.debug(str(type(content_decoded)))

    #taking the key from the CLI , as given by user
    input_key = args.key

    try:
        b64 = json.loads(content_decoded)
        json_k = ['nonce', 'header', 'ciphertext', 'tag','salt']
        jv = {k: b64decode(b64[k]) for k in json_k}
        logging.debug('the salt value is '+ str(jv['salt'])) #logging statement , please ignore

        crypto_key=PBKDF2(input_key, jv['salt'], 16)
        #we generate the crypto key based on the salt that we received

        cipher = AES.new(crypto_key, AES.MODE_GCM, nonce=jv['nonce'])
        cipher.update(jv['header'])

        decrypted_data_in_bytes = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
        #the above fucntion

        logging.debug('================================================DECRYPTION DONE ON ONE CHUNK OF DATA  =========================')
        logging.debug("The message was: " + str(decrypted_data_in_bytes))
        #ignore the debug statements above , i was using it for troubleshooting


        #the below lines will write the bytes to the STDOUT
        write_bytes_to_stdout(decrypted_data_in_bytes)
    except (ValueError, KeyError):
        logging.debug('Incorrect decryption due to the following :  1) wrong key or 2) err in socket communication 3) library is missing')

    pass


#this function writes the decrypted bytes out to STDOUT
def write_bytes_to_stdout(bytes_to_be_written):
    sys.stdout.buffer.write(bytes_to_be_written)
    pass


#setting up logging ( you can ignore this , as this will have no effect on anything )
logging.basicConfig(filename='log4.log',level=logging.DEBUG, filemode='w')

#configuring the argument parser

this_host=None
parser = argparse.ArgumentParser(description='Instance to parse the argument')
parser.add_argument('--key', metavar='', required=True , help = 'the key to be used for encryption / decryption ')
group=parser.add_mutually_exclusive_group(required=True)
group.add_argument('ip_address', type=str,help='serverIP', nargs = '?')
group.add_argument('-l', action='store_true')
parser.add_argument('port', metavar='', help = 'this is the port to connect to')
args=parser.parse_args()


#logic to check if it has to go in server on client
if args.l:
    logging.debug(' the -l parameter is present')
    this_host='server'
    server()        #calling the server function
else:
    logging.debug('the -l parameter is not present')
    this_host='client'
    client()        #calling the client function