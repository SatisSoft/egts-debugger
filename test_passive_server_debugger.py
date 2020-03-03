import socket
import threading
import time
import unittest
import sys
from io import StringIO

from egtsdebugger.passive_server_debugger import PassiveEgtsServerDebugger
from egtsdebugger.egts import *

auth_packet = b"\x01\x00\x00\x0b\x00\x0f\x00\x01\x00\x01\x06\x08\x00\x01\x00\x38\x01\x01\x05\x05\x00\x00\xef" \
              b"\x03\x00\x00\x07\xcd"
incorrect_reply = bytes([1, 0, 3, 11, 0, 16, 0, 9, 0, 0, 167, 9, 0, 0, 6, 0, 9, 0, 24, 2, 2, 0, 3, 0, 9, 0, 0, 0, 196])
reply_packet = bytes([1, 0, 3, 11, 0, 16, 0, 9, 0, 0, 167, 9, 0, 0, 6, 0, 9, 0, 24, 2, 2, 0, 3, 0, 9, 0, 0, 0, 195])

class TestPassiveServerDebugger(unittest.TestCase):
    """Tests for EgtsPassiveServerDebugger class"""

    def setUp(self):
        self.port = 9093
        self.host = 'localhost'
        self.dispatcher = 1007
        self.filename = 'data/2000_records.csv'

    def test_connection_error(self):
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        sever_thread = self.start_debugger_thread()
        self.start_test_server_connection_error()
        sever_thread.join()
        output = mystdout.getvalue()
        sys.stdout = old_stdout
        self.assertEqual("ERROR. server has closed the connection. No packets were received.\n", output)

    def test_incorrect_auth_message(self):
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        sever_thread = self.start_debugger_thread()
        self.start_test_server_incorrect_auth_message()
        sever_thread.join()
        output = mystdout.getvalue()
        sys.stdout = old_stdout
        self.assertEqual("ERROR. EGTS connection test failed: error parsing EGTS packet. Error code 128. Unsupported "
                         "protocol version (PRV not found).\n",
                         output)

    def test_incorrect_dispatcher_type(self):
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        sever_thread = self.start_debugger_thread()
        self.start_test_server_incorrect_dispatcher_type()
        sever_thread.join()
        output = mystdout.getvalue()
        sys.stdout = old_stdout
        msg = """Dispatcher Type must be equal to 0. Currently it is equal to 1
Error validating first packet: Packet ID: 1; Packet Type: 1; records: [{RecNum: 1, sst: 1, subrecords: [{Type: 5, dt: 1, did: 1007}]}]
ERROR. First packet is incorrect.
"""
        self.assertEqual(msg, output)

    def test_incorrect_dispatcher_id_message(self):
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        sever_thread = self.start_debugger_thread()
        self.start_test_server_incorrect_dispatcher_id_message()
        sever_thread.join()
        output = mystdout.getvalue()
        sys.stdout = old_stdout
        msg = """Expected Dispatcher ID = 1007 but got 2116
Error validating first packet: Packet ID: 1; Packet Type: 1; records: [{RecNum: 1, sst: 1, ID: 12, subrecords: [{Type: 5, dt: 0, did: 2116},{Type: 8},{Type: 8},{Type: 8},{Type: 8},{Type: 8}]}]
ERROR. First packet is incorrect.
"""
        self.assertEqual(msg, output)

    def test_success_1(self):
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        sever_thread = self.start_debugger_thread(**{'filename': "data/1_record.csv"})
        self.start_test_server_success(1)
        sever_thread.join()
        output = mystdout.getvalue()
        sys.stdout = old_stdout
        msg = """First packet is correct: Packet ID: 1; Packet Type: 1; records: [{RecNum: 1, sst: 1, subrecords: [{Type: 5, dt: 0, did: 1007}]}]
SUCCESS. EGTS connection test succeeded. Sent 1 packets including 1 records. Confirmation for all records were received.
"""
        self.assertEqual(msg, output)

    def test_success_5(self):
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        sever_thread = self.start_debugger_thread(**{'filename': "data/5_records.csv"})
        self.start_test_server_success(1)
        sever_thread.join()
        output = mystdout.getvalue()
        sys.stdout = old_stdout
        msg = """First packet is correct: Packet ID: 1; Packet Type: 1; records: [{RecNum: 1, sst: 1, subrecords: [{Type: 5, dt: 0, did: 1007}]}]
SUCCESS. EGTS connection test succeeded. Sent 1 packets including 5 records. Confirmation for all records were received.
"""
        self.assertEqual(msg, output)

    def test_success_2000(self):
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        sever_thread = self.start_debugger_thread()
        self.start_test_server_success(20)
        sever_thread.join()
        output = mystdout.getvalue()
        sys.stdout = old_stdout
        msg = """First packet is correct: Packet ID: 1; Packet Type: 1; records: [{RecNum: 1, sst: 1, subrecords: [{Type: 5, dt: 0, did: 1007}]}]
SUCCESS. EGTS connection test succeeded. Sent 20 packets including 2000 records. Confirmation for all records were received.
"""
        self.assertEqual(msg, output)

    def test_incorrect_egts_reply(self):
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        sever_thread = self.start_debugger_thread()
        self.start_test_incorrect_egts_reply()
        sever_thread.join()
        output = mystdout.getvalue()
        sys.stdout = old_stdout
        msg = """First packet is correct: Packet ID: 1; Packet Type: 1; records: [{RecNum: 1, sst: 1, subrecords: [{Type: 5, dt: 0, did: 1007}]}]
ERROR. EGTS connection test failed: error parsing EGTS packet. Error code 138. Data check sum error (Calculated crc: 49920, crc in packet: 50176).
"""
        self.assertEqual(msg, output)

    def test_unexpected_reply_success(self):
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        sever_thread = self.start_debugger_thread(**{'filename': "data/5_records.csv"})
        self.start_test_unexpected_reply_success()
        sever_thread.join()
        output = mystdout.getvalue()
        sys.stdout = old_stdout
        msg = """First packet is correct: Packet ID: 1; Packet Type: 1; records: [{RecNum: 1, sst: 1, subrecords: [{Type: 5, dt: 0, did: 1007}]}]
Warning: received unexpected replies: [9]
SUCCESS. EGTS connection test succeeded. Sent 1 packets including 5 records. Confirmation for all records were received.
"""
        self.assertEqual(msg, output)

    def test_unexpected_reply_failed(self):
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        sever_thread = self.start_debugger_thread(**{'filename': "data/5_records.csv"})
        self.start_test_unexpected_reply_failed()
        sever_thread.join()
        output = mystdout.getvalue()
        sys.stdout = old_stdout
        msg = """First packet is correct: Packet ID: 1; Packet Type: 1; records: [{RecNum: 1, sst: 1, subrecords: [{Type: 5, dt: 0, did: 1007}]}]
Warning: received unexpected replies: [9]
Error: did't receive reply on packets [1, 2, 3, 4, 5]
"""
        self.assertEqual(msg, output)

    def test_did_not_received_replies(self):
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        sever_thread = self.start_debugger_thread(**{'filename': "data/5_records.csv"})
        self.start_test_did_not_received_replies()
        sever_thread.join()
        output = mystdout.getvalue()
        sys.stdout = old_stdout
        msg = """First packet is correct: Packet ID: 1; Packet Type: 1; records: [{RecNum: 1, sst: 1, subrecords: [{Type: 5, dt: 0, did: 1007}]}]
ERROR. Sent 1 packets including 5 records, but received no replies from EGTS server.
"""
        self.assertEqual(msg, output)

    def test_socket_error(self):
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        sever_thread = self.start_debugger_thread(**{'filename': "data/2000_records.csv"})
        self.start_test_socket_error()
        sever_thread.join()
        output = mystdout.getvalue()
        sys.stdout = old_stdout
        msg = "First packet is correct: Packet ID: 1; Packet Type: 1; records: [{RecNum: 1, sst: 1, subrecords: [{" \
              "Type: 5, dt: 0, did: 1007}]}]\nERROR. Got socket error:"
        self.assertEqual(output.startswith(msg), True)


    def start_debugger_thread(self, **kwargs):
        if 'filename' in kwargs:
            filename = kwargs['filename']
        else:
            filename = self.filename
        egts_conn_test = PassiveEgtsServerDebugger(self.host, self.port, filename, self.dispatcher)
        debug_thread = threading.Thread(target=egts_conn_test.start)
        debug_thread.start()
        time.sleep(0.00001)
        return debug_thread

    def start_test_server_connection_error(self):
        sock = socket.socket()
        sock.connect((self.host, self.port))
        sock.close()

    def start_test_server_incorrect_auth_message(self):
        sock = socket.socket()
        sock.connect((self.host, self.port))
        msg = bytes(555)
        sock.send(msg)
        sock.close()

    def start_test_server_incorrect_dispatcher_type(self):
        sock = socket.socket()
        sock.connect((self.host, self.port))
        auth_packet = b"\x01\x00\x00\x0b\x00\x0f\x00\x01\x00\x01\x06\x08\x00\x01\x00\x38\x01\x01\x05\x05\x00\x01\xef" \
                      b"\x03\x00\x00\x56\x67"
        sock.send(auth_packet)
        sock.close()

    def start_test_server_incorrect_dispatcher_id_message(self):
        sock = socket.socket()
        sock.connect((self.host, self.port))
        auth_packet = b"\x01\x00\x00\x0B\x00\x35\x00\x01\x00\x01\x2B\x26\x00\x01\x00\x85\x0C\x00\x00\x00\xC9\xD7\x22" \
                      b"\x12\x01\x01\x05\x05\x00\x00\x44\x08\x00\x00\x08\x03\x00\x01\x00\x00\x08\x03\x00\x02\x00\x00" \
                      b"\x08\x03\x00\x04\x80\x00\x08\x03\x00\x09\x80\x00\x08\x03\x00\x0A\x80\x00\xAE\xD8"
        sock.send(auth_packet)
        sock.close()

    def start_test_server_success(self, num_of_packets):
        sock = socket.socket()
        sock.connect((self.host, self.port))
        sock.send(auth_packet)
        sock.recv(1024)
        buff = b""
        pid = 0
        rid = 0
        with sock:
            while pid < num_of_packets:
                data = sock.recv(1024)
                buff = buff + data
                try:
                    while len(buff) > 0:
                        egts = Egts(buff)
                        buff = egts.rest_buff
                        reply = egts.reply(pid, rid)
                        pid += 1
                        rid += 1
                        sock.send(reply)
                except EgtsParsingError:
                    continue

    def start_test_incorrect_egts_reply(self):
        sock = socket.socket()
        sock.connect((self.host, self.port))
        sock.send(auth_packet)
        sock.recv(1024)
        sock.recv(1024)
        sock.send(incorrect_reply)
        sock.close()

    def start_test_unexpected_reply_success(self):
        sock = socket.socket()
        sock.connect((self.host, self.port))
        sock.send(auth_packet)
        sock.recv(1024)
        data = sock.recv(1024)
        egts = Egts(data)
        reply = egts.reply(1, 1)
        sock.send(reply_packet)
        sock.send(reply)
        sock.close()

    def start_test_unexpected_reply_failed(self):
        sock = socket.socket()
        sock.connect((self.host, self.port))
        sock.send(auth_packet)
        sock.recv(1024)
        sock.recv(1024)
        sock.send(reply_packet)
        sock.close()

    def start_test_did_not_received_replies(self):
        sock = socket.socket()
        sock.connect((self.host, self.port))
        sock.send(auth_packet)
        sock.recv(1024)
        sock.recv(1024)
        sock.close()

    def start_test_socket_error(self):
        sock = socket.socket()
        sock.connect((self.host, self.port))
        sock.send(auth_packet)
        sock.recv(1024)
        sock.close()


    def _parse_egts(self, data):
        try:
            self.egts = Egts(data)
        except Exception as err:
            self.fail("Error while parsing EGTS:" + str(err))

if __name__ == '__main__':
    unittest.main()
