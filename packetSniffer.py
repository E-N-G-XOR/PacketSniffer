import struct
import textwrap
import socket

def main():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        rawData, address = connection.recvfrom(65535)
        reciever_mac, sender_mac, ethernetProtocol, data = ethernet_frame(rawData)
        print('\nEthernet Frame: ')
        print('Destination: {}, Source: {}, Protocol: {}'.format(reciever_mac, sender_mac, ethernetProtocol))

# Unpack ethernet frame
def ethernet_frame(data):
    reciever_mac, sender_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    return getMacAddress(reciever_mac), getMacAddress(sender_mac), socket.htons(protocol), data[14:]

# Convert the Mac address from the jumbled up form from above into human readable format
def getMacAddress(bytesAddress):
    bytesString = map('{:02x}'.format, bytesAddress)
    macAddress = ':'.join(bytesString).upper()
    return macAddress

#Unpack IP header data
def ip_packet(data):
    versionHeaderLength = data[0]
    version = versionHeaderLength >> 4
    headerLength = (versionHeaderLength & 15) * 4

    timeToLive, protocol, source, target = struct.unpack('! 8x B B  2x 4s 4s', data[:20])
    return version, headerLength, timeToLive, protocol, ip(source), ip(target), data[headerLength:]

#Returns properly formatted IP address
def ip(address):
    return '.'.join(map(str, address))

main()


























































