#CISC 420 Assignment 2: Packet Sniffer
#Douglas Bahr Rumbaugh

#A simple python packet sniffer built upon the Python socket interface.
#Designed to run on Windows NT(R) and requires Administrator access to run (required to set Promiscuous Mode)
import socket
import os
import struct
from ctypes import *
import crcmod

#Retrieve host IP address for use hosting the socket.
host = socket.gethostname()

#IP Header structure derived from the IP header definition in the C Standard Library.
#Implementation adapted from Chapter 3 of Justin Seitz's book _Black Hat Python_. 
class IP(Structure):
  _fields_ = [
    ("ihl",	c_ubyte, 4),
    ("version", c_ubyte, 4),
    ("tos", 	c_ubyte),
    ("lgnth", 	c_ushort),
    ("id", 	c_ushort),
    ("offset",	c_ushort),
    ("ttl",	c_ubyte),
    ("protocol_num", c_ubyte),
    ("sum",	     c_ushort),
    ("src",	     c_ulong),
    ("dst",	     c_ulong)
  ]

  def __new__(self, socket_buffer=None):
    return self.from_buffer_copy(socket_buffer)

  def __init__(self, socket_buffer=None):
    self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}

    self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
    self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))

    try:
      self.protocol = self.protocol_map[self.protocol_num]
    except:
      self.protocol = str(self.protocol_num)

#Formatted hexadecimal dump routine
#sourced from:  http://code.activestate.com/recipes/142812-hex-dumper
#written by:	George V. Reilly
def hexdump(src, length=16):
  result = []
  digits = 4 if isinstance(src, unicode) else 2

  for i in xrange(0, len(src), length):
    s = src[i:i+length]
    hexa = b' '.join(["%0*X" % (digits, ord(x)) for x in s])
    text = b''.join([x if 0x20 <= ord(x) < 0x7f else b'.' for x in s])
    result.append(b"%04X  %-*s  %s" % (i, length*(digits + 1), hexa, text))

  print b'\n'.join(result)

#Check that the header matches with the CRC value associated with it.
#The IPv4 CRC is checked by taking the complement of the sum
#of the entire header (including CRC). If this sum is 0, then the
#check is successful.
def check_crc(packet_header):
  def carry_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)

  header_hex = [] 

  for i in xrange(0, len(packet_header), 20):
    hexa = b' '.join(["%0*X" % (2, ord(x)) for x in packet_header])
    header_hex.append(hexa)
  
  header = header_hex[0].split()
  header = map(lambda x: int(x,16), header)
  header = struct.pack("%dB" % len(header), *header)
  checksum = 0
  for i in range (0, len(header), 2):
    checksum = carry_add(checksum, ord(header[i]) + (ord(header[i+1]) << 8))

  checksum = ~checksum & 0xffff
  print "CHECKSUM: 0x%04x" % (checksum)
  return checksum

def main():
  #Open a raw socket to recieve packets from the network across several protocols.
  sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
  sniffer.bind((host, 0))
  sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

  #Place host network adapter into Promiscuous mode to enable sniffing all packets traversing
  #the network.
  sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
  
  try:
    #Sniff packets from the network, and print to the console a formatted version of the
    #IP header information, and a formatted hex dump of the packet's body.
    while True:
      raw_buffer = sniffer.recvfrom(65565)[0]

      ip_header = IP(raw_buffer[0:20])

      print "\n\nProtocol: %s %s -> %s\nPacket Length: %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address, ip_header.lgnth)
      hexdump(raw_buffer[0:20])
      print ""
      hexdump(raw_buffer[21:])
      if (not check_crc(raw_buffer[0:20]) == 0):
        print "WARNING: CRC ERROR IN PACKET HEADER\a"
	#implement either bell or terminal flash. NT bell is ^G

  except KeyboardInterrupt:
    #Disable Promiscuous mode on the host network adapter and close the socket.
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    sniffer.close()


main()
