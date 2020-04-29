import socket
from egtsdebugger.egts import *

import traceback
import logging

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

    def start_listening(self, accept_loop = False):
        s = socket.socket()
        s.bind((self.host, self.port))
        s.listen(1)

        if accept_loop:
            while True:
                conn, addr = s.accept()
                self.handle_conn(conn)
        else:
            conn, addr = s.accept()
            self.handle_conn(conn)
            s.close()

    def handle_conn(self, conn):
        with conn:
            try:
                self._loop(conn)
            except EgtsParsingError as err:
                msg = "ERROR. EGTS connection test failed: error parsing EGTS packet. Error code {0}. {1}.".format(
                    err.error_code, err)
                logging.info(msg)
            except IncorrectNumberOfDispIdentity:
                logging.info(
                    "ERROR. EGTS connection test failed: The first packet must contain one "
                    "EGTS_SR_DISPATCHER_IDENTITY subrecord.")
            except IncorrectFirstPacket:
                logging.info("ERROR. First packet is incorrect.")
            except IncorrectNavPacket:
                logging.info("ERROR. EGTS connection test failed: Expected EGTS_SR_POS_DATA packet.")
            except UnexpectedDispatcherIdentity:
                logging.info(
                    "ERROR. Pass your Dispatcher ID as script arguments (-d option). If you do not have a Dispatcher "
                    "ID, set it to 1.")
            except Exception as err:
                logging.info("ERROR. EGTS connection test failed:", err)
                logging.info("trackback: ", traceback.format_exc())
            else:
                if self.num == self.max:
                    logging.info("SUCCESS. EGTS connection test succeeded. Received %d packets.", self.num)
                    logging.info("Please check in logs if data in packets is correct.")
                elif self.num == 1:
                    logging.info("ERROR. EGTS connection test failed: received only auth packet.")
                else:
                    logging.info("ERROR. Received only {0} packets, expected {1} packets.".format(self.num, self.max))

    def _loop(self, conn):
        buff = b""
        while self.max < 0 or self.num < self.max:
            data = conn.recv(1024)
            if not data and not buff and self.num == 0:
                logging.error("Error: received no data")
                break
            elif not data:
                logging.error("Not data")
                break
            buff = buff + data
            while len(buff) > 0:
                try:
                    if self.num == 0:
                        egts = self._validate_first_packet(buff)
                        logging.info("Received egts identify packet: %s", egts)
                    else:
                        egts = self._validate_nav_packet(buff)
                        logging.info("Received egts packet: %s", egts)
                    reply = egts.reply(self.pid, self.rid)
                    conn.send(reply)
                    self.pid += 1
                    self.rid += 1
                    self.num += 1
                    buff = egts.rest_buff
                except EgtsPcInvdatalen as err:
                    if len(buff) > EGTS_MAX_PACKET_LENGTH:
                        logging.error("Error parsing packet: %s %s", err, buff)
                        return
                    break

    def _validate_first_packet(self, data):
        egts = Egts(data)
        logging.info("Source Egts %s", egts)
        if self.did < 0:
            subs = self._found_dispatcher_identity(egts.records)
            if len(subs) > 1:
                logging.error("Error validating first packet: %s", egts)
                raise IncorrectNumberOfDispIdentity
            elif len(subs) == 1:
                [sub] = subs
                if not self._validate_dispatcher_identity_sub(sub, 1):
                    raise UnexpectedDispatcherIdentity
            logging.info("Received egts packet: %s", egts)
        else:
            subs = self._found_dispatcher_identity(egts.records)
            if len(subs) == 1:
                [sub] = subs
                if self._validate_dispatcher_identity_sub(sub, self.did):
                    logging.info("First packet is correct: %s", egts)
                    return egts
                else:
                    logging.info("Error validating first packet: %s", egts)
                    raise IncorrectFirstPacket
            else:
                logging.info("Error validating first packet: %s", egts)
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
            logging.info("Dispatcher Type must be equal to 0. Currently it is equal to %d", sub.dt)
            return False
        if sub.did != did:
            logging.info("Expected Dispatcher ID = %d but got %d", did, sub.did)
            return False
        return True

    @staticmethod
    def _validate_nav_packet(data):
        egts = Egts(data)
        return egts
