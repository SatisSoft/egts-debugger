import socket
from egts import *


class IncorrectFirstPacket(ValueError):
    pass


class IncorrectNavPacket(ValueError):
    pass


class EgtsServerDebugger:
    """Provides functional for testing EGTS server"""

    def __init__(self, host, port, num):
        self.host = host
        self.port = port
        self.num = 0
        self.max = num
        self.pid = 0
        self.rid = 0

    def start_listening(self):
        s = socket.socket()
        s.bind((self.host, self.port))
        s.listen(1)
        conn, addr = s.accept()
        with conn:
            data = conn.recv(1024)
            if not data:
                print("Error: received no data")
                s.close()
                return
            try:
                egts = self._validate_first_packet(data)
                reply = egts.reply(self.pid, self.rid)
                conn.send(reply)
                self.num += 1
                self.pid += 1
                self.rid += 1
                self._loop(conn)
            except EgtsParsingError as err:
                msg = "ERROR. EGTS connection test failed: error parsing EGTS packet. Error code {0}. {1}".format(err.error_code, err)
                print(msg)
            except IncorrectFirstPacket:
                print("ERROR. EGTS connection test failed: The first packet must be EGTS_SR_DISPATCHER_IDENTITY")
            except IncorrectNavPacket:
                print("ERROR. EGTS connection test failed: Expected EGTS_SR_POS_DATA packet")
            except Exception as err:
                print("ERROR. EGTS connection test failed:", err)
            else:
                if self.num == self.max:
                    print("SUCCESS. EGTS connection test succeeded. Received", self.num, "packets.")
                    print("Please check in logs if data in packets is correct.")
                elif self.num == 1:
                    print("ERROR. EGTS connection test failed: received only auth packet")
                else:
                    print("ERROR. Received only {0} packets, expected {1} packets.".format(self.num, self.max))
            finally:
                s.close()

    def _loop(self, conn):
        buff = b""
        while self.num < self.max:
            data = conn.recv(1024)
            if not data:
                break
            buff = buff + data
            while len(buff) > 0:
                try:
                    egts = self._validate_nav_packet(buff)
                    print("Received egts packet:", egts)
                    reply = egts.reply(self.pid, self.rid)
                    conn.send(reply)
                    self.pid += 1
                    self.rid += 1
                    self.num += 1
                    buff = egts.rest_buff
                except EgtsPcInvdatalen as err:
                    if len(buff) > 1024:
                        print("Error parsing packet:", err, buff)
                        buff = b""
                    break

    @staticmethod
    def _validate_first_packet(data):
        egts = Egts(data)
        [record] = egts.records
        [subrecord] = record.subrecords
        if type(subrecord) is EgtsSrDispatcherIdentity:
            print("First packet is correct:", egts)
            return egts
        else:
            print("Error validating first packet:", egts)
            raise IncorrectFirstPacket

    @staticmethod
    def _validate_nav_packet(data):
        egts = Egts(data)
        [record] = egts.records
        subrecords = record.subrecords
        for subrecord in subrecords:
            if type(subrecord) is not EgtsSrPosData:
                raise IncorrectNavPacket
        return egts
