import logging
import crcmod
from egtsdebugger.egts import *
import socket

auth_packet = b"\x01\x00\x00\x0b\x00\x0f\x00\x01\x00\x01\x06\x08\x00\x01\x00\x38\x01\x01\x05\x05\x00\x00\xef" \
              b"\x03\x00\x00\x07\xcd"
crc16_func = crcmod.mkCrcFun(0x11021, initCrc=0xFFFF, rev=False)


class RnisConnector:
    """Provide functional for connecting to RNIS"""

    def __init__(self, host, port, num, dispatcher, file):
        self.host = host
        self.port = port
        self.num = 0
        self.max = num
        self.did = dispatcher
        self.pid = 0
        self.rid = 0
        logging.basicConfig(filename=file, filemode='w', level=logging.INFO)

    def start(self):
        logging.info("start rnis_connector")
        s = socket.socket()
        s.connect((self.host, self.port))
        with s:
            try:
                self._sent_first_message(s)
                self._loop(s)
            except Exception as err:
                logging.error("EGTS connection test failed: %s", err)
            else:
                if self.num == self.max:
                    logging.info("Received %s packets", self.num)
            finally:
                s.close()

    def _sent_first_message(self, conn):
        msg = self._form_first_message()
        conn.send(msg)

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
                    logging.info("Received egts packet: %s", egts)
                    reply = egts.reply(self.pid, self.rid)
                    conn.send(reply)
                    self.pid += 1
                    self.rid += 1
                    self.num += 1
                    buff = egts.rest_buff
                except EgtsPcInvdatalen as err:
                    if len(buff) > 10000:
                        logging.error("Error parsing packet: %s; %s", err, buff)
                        buff = b""
                    break

    def _form_first_message(self):
        header = auth_packet[0:11]
        body = auth_packet[11:22] + self.did.to_bytes(4, 'little')
        bcs = crc16_func(body)
        bcs_bin = bcs.to_bytes(2, 'little')
        return header + body + bcs_bin

    @staticmethod
    def _validate_nav_packet(data):
        egts = Egts(data)
        return egts
