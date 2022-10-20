#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Sep 29 19:12:24 2022

@author: vaughn
"""



import socket
import argparse
import struct
import time
import sys






    

# Parsing Requirment
parser = argparse.ArgumentParser(description=('Uses TFTP over UDP to send or recieve files'))

parser.add_argument("-a", "--address", help=("remote host/server to communicate with"), required=True)
parser.add_argument("-f", "--filename", help = "name of file", required = True, type = str)
parser.add_argument("-p", "--clientport", help = "Local client port to use (default 5025", required=True, type = int)
parser.add_argument("-sp", "--serverport", help = "local server port to use", required=True, type = int)
parser.add_argument("-m", "--mode", help=("Mode of either reading or writing"), required=True, type=str)
args = parser.parse_args()





#Assigning Variables from the parse for use later

SERVER_ADDRESS = args.address
FILENAME = args.filename
CLIENT_PORT = args.clientport
SERVER_PORT = args.serverport
MODE = 'netascii'


# create socket if all parsing checks pass        
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2) # 3 second time out
SERVER = (SERVER_ADDRESS, SERVER_PORT)


# Failures if ports are out of range
if (CLIENT_PORT <5000 or  CLIENT_PORT> 65535):
    print("Invalid client port, must be between 5000 and 65535 (inclusive)\n" + "Please try again")
    parser.exit()
    
if (SERVER_PORT <5000 or  SERVER_PORT > 65535):
    print("Invalid server port, must be between 5000 and 65535 (inclusive)\n" + "Please try again")
    parser.exit()
    
# identify read or write mode or quit if invalid mode   
if args.mode != "r" and args.mode != "w": 
        print("Invalid mode, must be r (read) or w (write).\n" + "Please try again" )    
        SystemExit()
        
        


def build_request_packet(filename, mode, opcode):
    
    packet = bytearray()
    
    packet.append(0)
    packet.append(opcode)
    
    filename = bytearray(filename.encode('utf-8'))
    packet += filename
    packet.append(0)
    
    style = bytearray(bytes(mode, 'utf-8'))
    packet += style
    
    return packet

def build_rrq(filename, mode):
    opcode = 1
    return build_request_packet(filename, mode, opcode)

def build_wrq(filename, mode):
    opcode = 2
    return build_request_packet(filename, mode, opcode)


def build_data_packet(block, data):
    data_size = str(len(data))
    OpCode = 3
    data_string = '!HH' + data_size + 's'
    packet = struct.pack(data_string, OpCode, block, data)
    return packet

def build_error_packet(error_code):
    
    error_server_dict = {

        0: "Not defined, see error message (if any).",
        1: "File not found.",
        2: "Access violation.",
        3: "Disk full or allocation exceeded.",
        4: "Illegal TFTP operation.",
        5: "Unknown transfer ID.",
        6: "File already exists.",
        7: "No such user."
    }
    
    packet = bytearray()
    OpCode = 5
    
    packet.append(0)
    packet.append(OpCode)
    
    packet.append(0)
    packet.append(error_code)
    
    encode_msg = bytearray(error_server_dict[error_code].encode('utf-8'))
    
    packet += encode_msg
    packet.append(0)
    
    return packet


def build_ack_packet(block):
    OpCode = 4
    packet = bytearray()
    packet.append(0)
    packet.append(OpCode)
    packet.append(0)
    packet.append(block)
    
    return packet

def get_data(prev_block, data, filename):
    data = bytearray()

    fileEmpty = False
    with open(filename, "rb") as file:
        file.seek(prev_block * 512)
        data += file.read(512)

        if (file.read() == b''):
            fileEmpty = True
    
    return data, fileEmpty


def unpack_Data(filename, packet):
    opcode = packet[1]
    block = packet[3]
    byte_array_pointer = 4
    
    file_data = bytearray()
    
    if (len(packet) < 5):
        with open(filename, "ba") as file_object:
            file_object.close()
        
    else:
        while byte_array_pointer < len(packet):
            file_data.append(packet[byte_array_pointer])
            byte_array_pointer += 1
            
        with open(filename, "ba") as file_object:
            file_object.write(file_data)
            
    file_object.close()
    
    return opcode, block, file_data


def unpack_ACK(packet):
    block = packet[3]
    return block

def unpack_error(packet):
    error = packet[3]
    error_message = store_error_msg_bytes(packet)
    return error, error_message
    
    
    
def store_error_msg_bytes(packet):
    pointer = 4
    data = ''
    while pointer < len(packet) -1:
        bit = str(packet[pointer])
        data += bit
        pointer += 1
        
    return data
            


    
    

TIME_OUT_LENGTH = 3
DATA_MAX_LEN = 516
ENCODE = 'netascii'

#OPCODE dictionary
OPCODES = {
    'unknown' : 0,
    'read' : 1,
    'write' : 2,
    'data' : 3,
    'ack' : 4,
    'error' : 5
}

# Error dictionary
error_server_dict = {

    0: "Not defined, see error message (if any).",
    1: "File not found.",
    2: "Access violation.",
    3: "Disk full or allocation exceeded.",
    4: "Illegal TFTP operation.",
    5: "Unknown transfer ID.",
    6: "File already exists.",
    7: "No such user."
}

            
            

if __name__=="__main__":
    
    last_block = 0
    timeout = 0

    if (args.mode == 'w'):
        process_timer = time.time()
        
        data = ''
        check_address = ''
        packet = build_wrq(FILENAME, MODE)
        s.sendto(packet, SERVER)
        
        
        process_timeout = (time.time() - process_timer > 60.0)
        if (process_timeout):
            s.close()
            SystemExit()
            
        
        while (packet[1] ==2):
            
            if (timeout > 5):
                s.close()
                SystemExit()
     
            try: 
                packet, server_address = s.recvfrom(2048)
                
            except:
                s.sendto(packet, SERVER)
                timeout += 1
                continue
            
        check_address = server_address
        
        empty = True
        
        while (not empty):
            timer = time.time()
            duration = time.time() - timer
            
                
            if (packet[1] == 4):
                 
                if duration > 7.0:
                    s.close()
                    SystemExit()
                
                recieve_packet = unpack_ACK(packet)
                data, fileEmpty = get_data(last_block, data, FILENAME)
                if (not fileEmpty):
                    s.close()
                   

                last_block += 1
                packet = build_data_packet(last_block, data)
                s.sendto(packet, SERVER)
                
            if (server_address != check_address):
                packet = build_error_packet(5)
                s.sendto(packet, server_address)
                s.close()
                empty = False
                
            else:
                s.close()
               
                
                
    



    elif (args.mode == 'r'):
        
        packet = build_rrq(FILENAME, MODE)
        s.sendto(packet, SERVER)
        check_address = ''
       
        #print(SERVER)
        
        while packet[1] == 1:
            if (timeout > 5):
                s.close()
                SystemExit()
                
            try:
                packet, server_address = s.recvfrom(2048)
                check_address = server_address
                
            except:
                s.sendto(packet, SERVER)
                timeout += 1
                continue
                #maybe reset socket back to original instead of s
        recieve_array = unpack_Data(FILENAME, packet)
        #for (i = 0, i < 2, i++):
            #print(recieve_array[i])
        packet = build_ack_packet(last_block +1)
        s.sendto(packet, server_address)
        
        timeouts = 0
        timer = time.time()
        duration = time.time() - timer
        while (len(recieve_array[2]) == 512):
            if duration > 7.0:
                s.close()
                SystemExit()
            if (timeouts > 5):
                s.close()
                SystemExit()
            try:
                packet, server_address = s.recvfrom(2048)
            except:
                s.sendto(packet, server_address)
                timeouts += 1
                continue
            
            if (server_address != check_address):
                packet = build_error_packet(5)
                s.sendto(packet, server_address)
                s.close()
                
            elif packet[1] == 5:
                
                recieve_packet = unpack_error(packet)
                SystemExit()
                
            elif (packet[1] == 3):
                
                recieve_packet = unpack_Data(FILENAME, packet)
                packet = build_ack_packet(packet[2], packet[3])
                
                s.sendto(packet, SERVER)
                
                
  
                
        
        
    
  