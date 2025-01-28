# #################################################################################################################### #
# Imports                                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
import os
from socket import *
import struct
import time
import select


# #################################################################################################################### #
# Class IcmpHelperLibrary                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
class IcmpHelperLibrary:
    # ################################################################################################################ #
    # Class IcmpPacket                                                                                                 #
    #                                                                                                                  #
    # References:                                                                                                      #
    # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml                                           #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    
    class IcmpPacket:
        # ############################################################################################################ #
        # IcmpPacket Class Scope Variables                                                                             #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __icmpTarget = ""               # Remote Host
        __destinationIpAddress = ""     # Remote Host IP Address
        __header = b''                  # Header after byte packing
        __data = b''                    # Data after encoding
        __dataRaw = ""                  # Raw string data before encoding
        __icmpType = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __packetChecksum = 0            # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier = 0          # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber = 0      # Valid values are 0-65535 (unsigned short, 16 bits)
        __ipTimeout = 30
        __ttl = 255                     # Time to live

        __DEBUG_IcmpPacket = False      # Allows for debug output



        # ############################################################################################################ #
        # IcmpPacket Class Getters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpTarget(self):
            return self.__icmpTarget

        def getDataRaw(self):
            return self.__dataRaw

        def getIcmpType(self):
            return self.__icmpType

        def getIcmpCode(self):
            return self.__icmpCode

        def getPacketChecksum(self):
            return self.__packetChecksum

        def getPacketIdentifier(self):
            return self.__packetIdentifier

        def getPacketSequenceNumber(self):
            return self.__packetSequenceNumber

        def getTtl(self):
            return self.__ttl

        # ############################################################################################################ #
        # IcmpPacket Class Setters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIcmpTarget(self, icmpTarget):
            self.__icmpTarget = icmpTarget

            # Only attempt to get destination address if it is not whitespace
            if len(self.__icmpTarget.strip()) > 0:
                self.__destinationIpAddress = gethostbyname(self.__icmpTarget.strip())

        def setIcmpType(self, icmpType):
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode):
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier):
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber):
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl):
            self.__ttl = ttl

        # ############################################################################################################ #
        # IcmpPacket Class Private Functions                                                                           #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __recalculateChecksum(self):
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            packetAsByteData = b''.join([self.__header, self.__data])
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {"Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(checksum)) if self.__DEBUG_IcmpPacket else 0

            # Add 1's Complement Rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)   # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum              # Rotate and add

            answer = ~checksum                  # Invert bits
            answer = answer & 0xffff            # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self):
            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                   self.getIcmpType(),              #  8 bits / 1 byte  / Format code B
                                   self.getIcmpCode(),              #  8 bits / 1 byte  / Format code B
                                   self.getPacketChecksum(),        # 16 bits / 2 bytes / Format code H
                                   self.getPacketIdentifier(),      # 16 bits / 2 bytes / Format code H
                                   self.getPacketSequenceNumber()   # 16 bits / 2 bytes / Format code H
                                   )

        def __encodeData(self):
            data_time = struct.pack("d", time.time())               # Used to track overall round trip time
                                                                    # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.getDataRaw().encode("utf-8")

            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self):
            # Checksum is calculated with the following sequence to confirm data in up to date
            self.__packHeader()                 # packHeader() and encodeData() transfer data to their respective bit
                                                # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()        # Result will set new checksum value
            self.__packHeader()                 # Header is rebuilt to include new checksum value

        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):
            # Hint: Work through comparing each value and identify if this is a valid response.
            # validate sequence number 
            valid_sequenceNum = True if (self.getPacketSequenceNumber() == icmpReplyPacket.getIcmpSequenceNumber()) else False
            icmpReplyPacket.setIcmpSequence_isValid(valid_sequenceNum)
            
            # validate packet id 
            
            valid_packetId = True if (self.getPacketIdentifier() == icmpReplyPacket.getIcmpIdentifier()) else False
            icmpReplyPacket.setIcmpIdentifier_isValid(valid_packetId)

            # validate data
            valid_data = True if (self.getDataRaw() == icmpReplyPacket.getIcmpData()) else False
                
            icmpReplyPacket.setIcmpData_isValid(valid_data)

            # validate response
            valid_response = True if (valid_sequenceNum and valid_packetId and valid_data) else False
            icmpReplyPacket.setIcmpResponse_isValid(valid_response)

            # create debug message with validation statuses. 
            debugMsg = (
                f"Valid icmp Reply Packet: {valid_response}\n"
                f"  Sequence Number: Valid = {valid_sequenceNum}, Sent = {self.getPacketSequenceNumber()}, Recieved = {icmpReplyPacket.getIcmpSequenceNumber()}\n"        
                f"  Packet ID Number: Valid = {valid_packetId}, Sent = {self.getPacketIdentifier()}, Recieved = {icmpReplyPacket.getIcmpIdentifier()}\n"
                f"  Data: Valid = {valid_data}, Sent = {self.getDataRaw()}, Recieved = {icmpReplyPacket.getIcmpData()}\n"        
            )

            print(debugMsg)


        # ############################################################################################################ #
        # IcmpPacket Class Public Functions                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber):
            self.setIcmpType(8)
            self.setIcmpCode(0)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()
        
        def sendEchoRequest(self):
            if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            print("Pinging (" + self.__icmpTarget + ") " + self.__destinationIpAddress)
            

            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.getTtl()))  # Unsigned int - 4 bytes
            try:
                

                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeLeft = 30
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)
                if whatReady[0] == []:  # Timeout
                    print("  *        *        *        *        *    Request timed out.")
                recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                # addr  - address of socket sending data
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    print("  *        *        *        *        *    Request timed out (By no remaining time left).")

                else:
                    # Fetch the ICMP type and code from the received packet
                    icmpType, icmpCode = recvPacket[20:22]
                    

                    if icmpType == 11:                          # Time Exceeded
                        errorMessage = self.readIcmpErrorMessage(11, icmpCode)
                        print(errorMessage)
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                                (
                                    self.getTtl(),
                                    (timeReceived - pingStartTime) * 1000,
                                    icmpType,
                                    icmpCode,
                                    addr[0]
                                )
                              )

                    elif icmpType == 3:                         # Destination Unreachable
                        errorMessage = self.readIcmpErrorMessage(3, icmpCode)
                        # added error handling
                        print(errorMessage)
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                                  (
                                      self.getTtl(),
                                      (timeReceived - pingStartTime) * 1000,
                                      icmpType,
                                      icmpCode,
                                      addr[0]
                                  )
                              )

                    elif icmpType == 0:                         # Echo Reply
                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket)
                        self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
                        icmpReplyPacket.printResultToConsole(self.getTtl(), timeReceived, addr)

                        
                        return      # Echo reply is the end and therefore should return

                    else:
                        print("error")
            except timeout:
                print("  *        *        *        *        *    Request timed out (By Exception).")
            finally:
                mySocket.close()    
        """
        Helper function that reads error codes and returns human readable code
        """
        def readIcmpErrorMsg(self, errorType, errorCode):
            icmbErrorCode_dict = {
                0:	"Echo reply",
                3:  {
                    0:	"Net Unreachable",
                    1:	"Host Unreachable",
                    2:	"Protocol Unreachable",
                    3:	"Port Unreachable",
                    4:	"Fragmentation Needed and Do not Fragment was Set",
                    5:	"Source Route Failed",
                    6:	"Destination Network Unknown",
                    7:	"Destination Host Unknown",
                    8:	"Source Host Isolated",
                    9:	"Communication with Destination Network is Administratively Prohibited",
                    10:	"Communication with Destination Host is Administratively Prohibited",
                    11:	"Destination Network Unreachable for Type of Service",
                    12:	"Destination Host Unreachable for Type of Service",
                    13:	"Communication Administratively Prohibited",
                    14:	"Host Precedence Violation",
                    15:	"Precedence cutoff in effect",
                    },
                11: {
                    0:	"Time to Live exceeded in Transit",
                    1:	"Fragment Reassembly Time Exceeded",
                    },
            }
            return icmbErrorCode_dict.get(errorType, {}).get(errorCode, "Unknown Error")

            
        def printIcmpPacketHeader_hex(self):
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i+1].hex())

        def printIcmpPacketData_hex(self):
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()

    # ################################################################################################################ #
    # Class IcmpPacket_EchoReply                                                                                       #
    #                                                                                                                  #
    # References:                                                                                                      #
    # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm                                                         #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket_EchoReply:
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Class Scope Variables                                                                   #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        #variables added for validation 
        __recvPacket = b''
        __isValidResponse = False
        IcmpIdentifier_isValid = False
        IcmpSequence_isValid = False
        IcmpData_isValid = False
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Constructors                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __init__(self, recvPacket, sentSequence = None, sentIdentifier = None, sentData = None):
            self.__recvPacket = recvPacket
            self.sentSequence = sentSequence
            self.sentIdentifier = sentIdentifier
            self.sentData = sentData

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Getters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpType(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 20)

        def getIcmpCode(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 21)

        def getIcmpHeaderChecksum(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 22)

        def getIcmpIdentifier(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 24)

        def getIcmpSequenceNumber(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 26)

        def getDateTimeSent(self):
            # This accounts for bytes 28 through 35 = 64 bits
            return self.__unpackByFormatAndPosition("d", 28)   # Used to track overall round trip time
                                                               # time.time() creates a 64 bit value of 8 bytes

        def getIcmpData(self):
            # This accounts for bytes 36 to the end of the packet.
            return self.__recvPacket[36:].decode('utf-8')

        # return if the response, id, sequence, and data are valid
        def isValidResponse(self):
            return self.__isValidResponse
        
        def getIcmpIdentifier_isValid(self):
            return self.IcmpIdentifier_isValid
        
        def getIcmpSequence_isValid(self):
            return self.IcmpSequence_isValid
        
        def getIcmpData_isValid(self):
            return self.IcmpData_isValid
        


        # ############################################################################################################ #
        # IcmpPacket_EchoReply Setters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        # set class variables, valid, id, sequence, and data 
        def setIcmpResponse_isValid(self, booleanValue):
            self.IcmpResponse_isValid = booleanValue

        def setIcmpIdentifier_isValid(self, booleanValue):
            self.IcmpIdentifier_isValid = booleanValue
            
        def setIcmpSequence_isValid(self, booleanValue):
            self.IcmpSequence_isValid = booleanValue
            
        def setIcmpData_isValid(self, booleanValue):
            self.IcmpData_isValid = booleanValue

        

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Private Functions                                                                       #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Public Functions                                                                        #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def printResultToConsole(self, ttl, timeReceived, addr):
            bytes = struct.calcsize("d")
            timeSent = struct.unpack("d", self.__recvPacket[28:28 + bytes])[0]
            
            if self.isValidResponse():          
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d        Identifier=%d    Sequence Number=%d    %s" %
                    (
                        ttl,
                        (timeReceived - timeSent) * 1000,
                        self.getIcmpType(),
                        self.getIcmpCode(),
                        self.getIcmpIdentifier(),
                        self.getIcmpSequenceNumber(),
                        addr[0]
                    )
                    )
            # else branching that explains what is wrong and why    
            else:
                print
                (f"Valid icmp Reply Packet: {self.isValidResponse()}\n")

                if not self.getIcmpSequence_isValid:
                    print(f"Invalid Sequence Number: Sent = {self.sentIdentifier}, Recieved = {self.getIcmpIdentifier}")

                if not self.getIcmpIdentifier_isValid:
                    print(f"Invalid Identifier: Sent = {self.sentIdentifier}, Recieved = {self.getIcmpIdentifier}")

                if not self.getIcmpData_isValid:
                    print(f"Invalid Data: Sent = {self.sentData}, Recieved = {self.getIcmpData}")

    # ################################################################################################################ #
    # Class IcmpHelperLibrary                                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #


    # ################################################################################################################ #
    # IcmpHelperLibrary Class Scope Variables                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    __DEBUG_IcmpHelperLibrary = False                  # Allows for debug output
    
    """
    Class built to help keep track of ping
    """
    class PingStats:
        def __init__(self):
            self.rtts = []
            self.sentPackets = 0
            self.recievedPackets = 0
            
        def add_rtts(self, rtt):
            self.rtts.append(rtt)
            self.recievedPackets += 1

        def add_recievedPacket(self):
            self.sentPackets += 1

        def lossRate(self):
            loss = 100.0 * (self.sentPackets - self.recievedPackets) / self.sentPackets
            if (loss > 0):
                return loss
            return 0
                
        def print_pingSummary(self, destination):
            min_rtt = min(self.rtts) if self.rtts else 0
            max_rtt = max(self.rtts) if self.rtts else 0
            avg_rtt = sum(self.rtts) / len(self.rtts) if self.rtts else 0
                    
            print(f"{destination} Ping Stats")
            print(f" Packets Sent: {self.sentPackets}"
                f"\n Packets Recieved: {self.recievedPackets}"
                f"\n Loss Rate: {self.lossRate()}%"
                )
            if self.rtts:
                print(f" rtt Stats: Min {min_rtt:.2f}ms, Max {max_rtt:.2f}ms, Avg {avg_rtt:.2f}ms")
    # ################################################################################################################ #
    # IcmpHelperLibrary Private Functions                                                                              #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    
    
    
    def __sendIcmpEchoRequest(self, host):
        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        stats = self.PingStats()
        for i in range(4):
            stats.add_recievedPacket()
            # Build packet
           
            icmpPacket = IcmpHelperLibrary.IcmpPacket()

            randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number - Limit based on ICMP header standards
                                                           # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = i

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)

            startTime = time.time()
            icmpPacket.sendEchoRequest()                                                # Build IP
            endTime = time.time()

            rtt = (endTime - startTime) * 1000
            stats.add_rtts(rtt)

            icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0
        stats.print_pingSummary(host)
            # we should be confirming values are correct, such as identifier and sequence number and data


    def __sendIcmpTraceRoute(self, host):
        print("sendIcmpTraceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        # Build code for trace route here

    # ################################################################################################################ #
    # IcmpHelperLibrary Public Functions                                                                               #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def sendPing(self, targetHost):
        print("ping Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpEchoRequest(targetHost)

    def traceRoute(self, targetHost):
        print("traceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpTraceRoute(targetHost)


# #################################################################################################################### #
# main()                                                                                                               #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
def main():
    icmpHelperPing = IcmpHelperLibrary()


    # Choose one of the following by uncommenting out the line
    # icmpHelperPing.sendPing("www.cityoflondon.gov.uk")
    # icmpHelperPing.sendPing("www.governo.it")
    # icmpHelperPing.sendPing("www.crunchyroll.com")
    # icmpHelperPing.sendPing("www.google.com")
    # icmpHelperPing.sendPing("gaia.cs.umass.edu")
    # icmpHelperPing.traceRoute("164.151.129.20")
    # icmpHelperPing.traceRoute("122.56.99.243")


if __name__ == "__main__":
    main()
