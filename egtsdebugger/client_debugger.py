import socket
from egtsdebugger.egts import *


class IncorrectNumberOfDispIdentity(ValueError):
    pass

class IncorrectFirstPacket(ValueError):
    pass

class IncorrectNavPacket(ValueError):
    pass

class UnexpectedDispatcherIdentity(ValueError):
    pass


class EgtsClientDebugger:
    """Provides functional for testing EGTS client"""

    def __init__(self, host, port, num, dispatcher):
        self.host = host
        self.port = port
        self.num = 0
        self.max = num
        self.pid = 0
        self.rid = 0
        self.did = dispatcher

    def start_listening(self):
        s = socket.socket()
        s.bind((self.host, self.port))
        s.listen(1)
        conn, addr = s.accept()
        with conn:
            try:
                data = conn.recv(1024)
                if not data:
                    print("Error: received no data")
                    s.close()
                    return
                egts = self._validate_first_packet(data)
                reply = egts.reply(self.pid, self.rid)
                conn.send(reply)
                self.num += 1
                self.pid += 1
                self.rid += 1
                self._loop(conn)
            except EgtsParsingError as err:
                msg = "ERROR. EGTS connection test failed: error parsing EGTS packet. Error code {0}. {1}.".format(err.error_code, err)
                print(msg)
            except IncorrectNumberOfDispIdentity:
                print("ERROR. EGTS connection test failed: The first packet must contain one EGTS_SR_DISPATCHER_IDENTITY subrecord.")
            except IncorrectFirstPacket:
                print("ERROR. First packet is incorrect.")
            except IncorrectNavPacket:
                print("ERROR. EGTS connection test failed: Expected EGTS_SR_POS_DATA packet.")
            except UnexpectedDispatcherIdentity:
                print("ERROR. Pass your Dispatcher ID as script arguments (-d option). If you do not have a Dispatcher ID, set it to 1.")
            except Exception as err:
                print("ERROR. EGTS connection test failed:", err)
            else:
                if self.num == self.max:
                    print("SUCCESS. EGTS connection test succeeded. Received", self.num, "packets.")
                    print("Please check in logs if data in packets is correct.")
                elif self.num == 1:
                    print("ERROR. EGTS connection test failed: received only auth packet.")
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

    def _validate_first_packet(self, data):
        egts = Egts(data)
        if self.did < 0:
            subs = self._found_dispatcher_identity(egts.records)
            if len(subs) > 1:
                print("Error validating first packet:", egts)
                raise IncorrectNumberOfDispIdentity
            elif len(subs) == 1:
                [sub] = subs
                if not self._validate_dispatcher_identity_sub(sub, 1):
                    raise UnexpectedDispatcherIdentity
            print("Received egts packet:", egts)
        else:
            subs = self._found_dispatcher_identity(egts.records)
            if len(subs) == 1:
                [sub] = subs
                if self._validate_dispatcher_identity_sub(sub, self.did):
                    print("First packet is correct:", egts)
                    return egts
                else:
                    print("Error validating first packet:", egts)
                    raise IncorrectFirstPacket
            else:
                print("Error validating first packet:", egts)
                raise IncorrectNumberOfDispIdentity
        return egts

    @staticmethod
    def _found_dispatcher_identity(records):
        subs = []
        for record in records:
            for sub in record.subrecords:
                if type(sub) is EgtsSrDispatcherIdentity:
                    subs.append(sub)
        return subs

    @staticmethod
    def _validate_dispatcher_identity_sub(sub, did):
        if sub.dt != 0:
            print("Dispatcher Type must be equal to 0. Currently it is equal to", sub.dt)
            return False
        if sub.did != did:
            print("Expected Dispatcher ID =", did, "but got", sub.did)
            return False
        return True

    @staticmethod
    def _validate_nav_packet(data):
        egts = Egts(data)
        return egts


