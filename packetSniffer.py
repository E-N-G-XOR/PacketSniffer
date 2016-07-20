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

main()


























































