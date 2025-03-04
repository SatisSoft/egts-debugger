import logging
from egtsdebugger.egts import *
import socket

class RnisConnector:
    """Provide functional for connecting to RNIS"""

    def __init__(self, host, port, num, dispatcher, file, **kwargs):
        self.host = host
        self.port = port
        self.num = 0
        self.max = num
        self.did = dispatcher
        self.pid = 0
        self.rid = 0
        self.login = kwargs.get('login')
        self.password = kwargs.get('password')
        self.buffer = b''
        logging.basicConfig(filename=file, filemode='w', level=logging.INFO)

    def start(self):
        logging.info("start rnis_connector")
        s = socket.socket()
        s.connect((self.host, self.port))
        with s:
            try:
                if self._auth(s):
                    self._loop(s)
                else:
                    logging.error("EGTS authorization failed")
            except Exception as err:
                logging.error("EGTS connection test failed: %s", err)
            else:
                if self.num == self.max:
                    logging.info("Received %s packets", self.num)
            finally:
                s.close()

    def _auth(self, conn):
        subrec = EgtsSrDispatcherIdentity(EGTS_SR_DISPATCHER_IDENTITY, dt=0, did=self.did)
        response = self._send_auth_packet(conn, subrec)
        logging.info("Received egts packet: %s", response)
        if not self._check_response(response):
            return False

        if self.did == 0xFFffFFff:
            auth_params = self._receive_packet(conn)
            logging.info("Received egts packet: %s", auth_params)
            self._send_replay(conn, auth_params)
            if not self._check_auth_params(auth_params):
                return False

            subrec = EgtsSrAuthInfo(EGTS_SR_AUTH_INFO, unm=self.login, upsw=self.password)
            response = self._send_auth_packet(conn, subrec)
            logging.info("Received egts packet: %s", response)
            if not self._check_response(response):
                return False

        result_code = self._receive_packet(conn)
        logging.info("Received egts packet: %s", result_code)
        self._send_replay(conn, result_code)
        if not self._check_result_code(result_code):
            return False
        return True

    def _loop(self, conn):
        while self.num < self.max:
            egts = self._receive_packet(conn)
            self._send_replay(conn, egts)
            self.num += 1
            logging.info("Received egts packet: %s", egts)

    def _receive_packet(self, conn):
        while len(self.buffer) <= EGTS_MAX_PACKET_LENGTH:
            if self.buffer == b'':
                data = conn.recv(1024)
                if not data:
                    return None
                else:
                    self.buffer += data
            try:
                egts = Egts(self.buffer)
                self.buffer = egts.rest_buff
                return egts
            except EgtsPcInvdatalen as err:
                data = conn.recv(1024)
                if not data:
                    return None
                else:
                    self.buffer += data

    def _send_replay(self, conn, egts):
        reply = egts.reply(self.pid, self.rid)
        conn.send(reply)
        self._pid_increment()
        self._rid_increment()

    def _send_auth_packet(self, conn, subrec):
        egts_record = EgtsRecord(rid=self.rid, sst=EGTS_AUTH_SERVICE, subrecords=[subrec])
        packet = Egts.form_bin(self.pid, [egts_record])
        conn.send(packet)
        self._pid_increment()
        self._rid_increment()
        response = self._receive_packet(conn)
        return response

    def _pid_increment(self):
        self.pid += 1
        if self.pid > 0xFFff:
            self.pid = 0

    def _rid_increment(self):
        self.rid += 1
        if self.rid > 0xFFff:
            self.rid = 0

    @staticmethod
    def _check_response(packet):
        for record in packet.records:
            for subrec in record.subrecords:
                if subrec.rst != 0:
                    return False
        else:
            return True

    @staticmethod
    def _check_auth_params(packet):
        if packet.records[0].subrecords[0].flg != 0:
            return False
        else:
            return True

    @staticmethod
    def _check_result_code(packet):
        if packet.records[0].subrecords[0].rcd != 0:
            return False
        else:
            return True
