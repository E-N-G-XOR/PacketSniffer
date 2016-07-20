import struct
import textwrap
import socket

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '


def main():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        rawData, address = connection.recvfrom(65535)
        reciever_mac, sender_mac, ethernetProtocol, data = ethernet_frame(rawData)
        print('\nEthernet Frame: ')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(reciever_mac, sender_mac, ethernetProtocol))

        #Make sure you are using Ethernet protocol 8
        if ethernetProtocol == 8:
            (version, headerLength, timeToLive, protocol, source, target, data) = ip(data)
            print(TAB_1 + 'IP Packet:')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, headerLength, timeToLive))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(protocol, source, target))

            if protocol == 1:
                icmpType, code, checkSum, data = icmpPackets(data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmpType, code, checkSum))
                print(TAB_2 + 'Data:')
                print(formatMultiLine(DATA_TAB_3, data))

            elif protocol == 6:
                (sourcePort, destinationPort, sequence, acknowledgement, flagURG, flagACK, flagPSH, flagRST, flagSYN, flagFIN, data) = tcpSegment(data)
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(sourcePort, destinationPort))
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgement))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(flagURG, flagACK, flagPSH))
                print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(flagRST, flagSYN, flagSYN))
                print(formatMultiLine(DATA_TAB_3, data))

            elif protocol == 17:
                (sourcePort, destinationPort, length, data) = udpSegment(data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(sourcePort, destinationPort, length))

            else:
                print(TAB_1 + 'Other IPv4 Data:')
                print(formatMultiLine(DATA_TAB_2, data))

        else:
            print('Ethernet Data:')
            print(formatMultiLine(DATA_TAB_1, data))


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

#Unpack ICMP packets
def icmpPackets(data):
    icmpType, code, checkSum = struct.unpack('! B B H', data[:4])
    return icmpType, code, checkSum, data[4:]

#Unpack TCP segments:
def tcpSegment(data):
    (sourcePort, destinationPort, sequence, acknowledgement, offsetReservedFlags) = struct.unpack('! H H L L H', data[:14])
    offset = (offsetReservedFlags >> 12) * 4

    flagURG = (offsetReservedFlags & 32) >> 5
    flagACK = (offsetReservedFlags & 16) >> 4
    flagPSH = (offsetReservedFlags & 8) >> 3
    flagRST = (offsetReservedFlags & 4) >> 2
    flagSYN = (offsetReservedFlags & 2) >> 1
    flagFIN = offsetReservedFlags & 1

    return sourcePort, destinationPort, sequence, acknowledgement, flagURG, flagACK, flagPSH, flagRST, flagSYN, flagFIN, data[offset:]

#Unpack UDP segments:
def udpSegment(data):
    sourcePort, destinationPort, size = struct.unpack('! H H 2x H', data[:8])
    return sourcePort, destinationPort, size, data[8:]

#Breaks down and formats large, multi-lined data
def formatMultiLine(prefix, string, size = 80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02X}'.format(byte) for byte in string)
        if size % 2:
            size -= 1

    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

main()


























































