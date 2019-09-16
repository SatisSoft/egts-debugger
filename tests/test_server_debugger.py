import socket
import threading
import time
import unittest
import sys
from io import StringIO

from server_debugger import EgtsServerDebugger
from egts import *


class TestServerDebugger(unittest.TestCase):
    """Tests for EgtsServerDebugger class"""

    def setUp(self):
        self.port = 9092
        self.host = 'localhost'
        self.num = 10

    def test_disconnect(self):
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        sever_thread = self.start_server_thread()
        self.start_test_client_disconnect()
        sever_thread.join()
        output = mystdout.getvalue()
        sys.stdout = old_stdout
        self.assertEqual("Error: received no data\n", output)

    def test_wrong_message(self):
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        sever_thread = self.start_server_thread()
        self.start_test_client_wrong_message()
        sever_thread.join()
        output = mystdout.getvalue()
        sys.stdout = old_stdout
        self.assertEqual("ERROR. EGTS connection test failed: error parsing EGTS packet. Error code 128. Unsupported protocol version (PRV not found)\n",
                         output)

    def test_success(self):
        self.num = 3
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        sever_thread = self.start_server_thread()
        self.start_test_client_success()
        sever_thread.join()
        output = mystdout.getvalue()
        sys.stdout = old_stdout
        msg = """First packet is correct: Packet ID: 1; Packet Type: 1; records: [{RecNum: 1, sst: 1, subrecords: [{Type: 5, dt: 0, did: 1007}]}]
Received egts packet: Packet ID: 0; Packet Type: 1; records: [{RecNum: 0, sst: 2, ID: 239, subrecords: [{Type: 16, vld: True, ntm: 1533570258000, lat: 55.62752532903746, long: 37.782409656276556, speed: 0, dir: 178, busy: 0, src: 0}]}]
Received egts packet: Packet ID: 0; Packet Type: 1; records: [{RecNum: 0, sst: 2, ID: 239, subrecords: [{Type: 16, vld: True, ntm: 1533570258000, lat: 55.62752532903746, long: 37.782409656276556, speed: 0, dir: 178, busy: 0, src: 0}]}]
SUCCESS. EGTS connection test succeeded. Received 3 packets.
Please check in logs if data in packets is correct.
"""
        self.assertEqual(msg, output)

    def test_second_nav_incorrect(self):
        self.num = 3
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        sever_thread = self.start_server_thread()
        self.start_test_client_second_nav_incorrect()
        sever_thread.join()
        output = mystdout.getvalue()
        sys.stdout = old_stdout
        msg = """First packet is correct: Packet ID: 1; Packet Type: 1; records: [{RecNum: 1, sst: 1, subrecords: [{Type: 5, dt: 0, did: 1007}]}]
Received egts packet: Packet ID: 0; Packet Type: 1; records: [{RecNum: 0, sst: 2, ID: 239, subrecords: [{Type: 16, vld: True, ntm: 1533570258000, lat: 55.62752532903746, long: 37.782409656276556, speed: 0, dir: 178, busy: 0, src: 0}]}]
ERROR. EGTS connection test failed: error parsing EGTS packet. Error code 138. Data check sum error (Calculated crc: 27112, crc in packet: 36202)
"""
        self.assertEqual(msg, output)

    def test_not_enough_packets(self):
        self.num = 5
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        sever_thread = self.start_server_thread()
        self.start_test_client_success()
        sever_thread.join()
        output = mystdout.getvalue()
        sys.stdout = old_stdout
        msg = """First packet is correct: Packet ID: 1; Packet Type: 1; records: [{RecNum: 1, sst: 1, subrecords: [{Type: 5, dt: 0, did: 1007}]}]
Received egts packet: Packet ID: 0; Packet Type: 1; records: [{RecNum: 0, sst: 2, ID: 239, subrecords: [{Type: 16, vld: True, ntm: 1533570258000, lat: 55.62752532903746, long: 37.782409656276556, speed: 0, dir: 178, busy: 0, src: 0}]}]
Received egts packet: Packet ID: 0; Packet Type: 1; records: [{RecNum: 0, sst: 2, ID: 239, subrecords: [{Type: 16, vld: True, ntm: 1533570258000, lat: 55.62752532903746, long: 37.782409656276556, speed: 0, dir: 178, busy: 0, src: 0}]}]
ERROR. Received only 3 packets, expected 5 packets.
"""
        self.assertEqual(msg, output)

    def test_only_auth(self):
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        sever_thread = self.start_server_thread()
        self.start_test_client_only_auth()
        sever_thread.join()
        output = mystdout.getvalue()
        sys.stdout = old_stdout
        msg = """First packet is correct: Packet ID: 1; Packet Type: 1; records: [{RecNum: 1, sst: 1, subrecords: [{Type: 5, dt: 0, did: 1007}]}]
ERROR. EGTS connection test failed: received only auth packet
"""
        self.assertEqual(msg, output)

    def test_two_auth(self):
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        sever_thread = self.start_server_thread()
        self.start_test_client_two_auth()
        sever_thread.join()
        output = mystdout.getvalue()
        sys.stdout = old_stdout
        msg = """First packet is correct: Packet ID: 1; Packet Type: 1; records: [{RecNum: 1, sst: 1, subrecords: [{Type: 5, dt: 0, did: 1007}]}]
ERROR. EGTS connection test failed: Expected EGTS_SR_POS_DATA packet
"""
        self.assertEqual(msg, output)

    def test_first_not_auth(self):
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        sever_thread = self.start_server_thread()
        self.start_test_first_not_auth()
        sever_thread.join()
        output = mystdout.getvalue()
        sys.stdout = old_stdout
        msg = """Error validating first packet: Packet ID: 0; Packet Type: 1; records: [{RecNum: 0, sst: 2, ID: 239, subrecords: [{Type: 16, vld: True, ntm: 1533570258000, lat: 55.62752532903746, long: 37.782409656276556, speed: 0, dir: 178, busy: 0, src: 0}]}]
ERROR. EGTS connection test failed: The first packet must be EGTS_SR_DISPATCHER_IDENTITY
"""
        self.assertEqual(msg, output)

    def test_first_incorrect(self):
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        sever_thread = self.start_server_thread()
        self.start_test_first_incorrect()
        sever_thread.join()
        output = mystdout.getvalue()
        sys.stdout = old_stdout
        msg = "ERROR. EGTS connection test failed: error parsing EGTS packet. Error code 137. Header check sum error (Calculated crc: 122, crc in packet: 6)\n"
        self.assertEqual(msg, output)

    def test_nav_incorrect(self):
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        sever_thread = self.start_server_thread()
        self.start_test_nav_incorrect()
        sever_thread.join()
        output = mystdout.getvalue()
        sys.stdout = old_stdout
        msg = """First packet is correct: Packet ID: 1; Packet Type: 1; records: [{RecNum: 1, sst: 1, subrecords: [{Type: 5, dt: 0, did: 1007}]}]
ERROR. EGTS connection test failed: error parsing EGTS packet. Error code 128. Unsupported protocol version (PRV not found)
"""
        self.assertEqual(msg, output)

    def start_server_thread(self):
        egts_conn_test = EgtsServerDebugger(self.host, self.port, self.num)
        server_thread = threading.Thread(target=egts_conn_test.start_listening)
        server_thread.start()
        time.sleep(0.00001)
        return server_thread

    def start_test_client_disconnect(self):
        sock = socket.socket()
        sock.connect((self.host, self.port))
        sock.close()

    def start_test_client_wrong_message(self):
        sock = socket.socket()
        sock.connect((self.host, self.port))
        msg = bytes(555)
        sock.send(msg)
        sock.close()

    def start_test_client_success(self):
        sock = socket.socket()
        sock.connect((self.host, self.port))
        auth_packet = b"\x01\x00\x00\x0b\x00\x0f\x00\x01\x00\x01\x06\x08\x00\x01\x00\x38\x01\x01\x05\x05\x00\x00\xef" \
                      b"\x03\x00\x00\x07\xcd"
        sock.send(auth_packet)
        _ = sock.recv(1024)
        nav_packet = b"\x01\x00\x00\x0b\x00\x23\x00\x00\x00\x01\x99\x18\x00\x00\x00\x01\xef\x00\x00\x00\x02\x02\x10" \
                     b"\x15\x00\xd2\x31\x2b\x10\x4f\xba\x3a\x9e\xd2\x27\xbc\x35\x03\x00\x00\xb2\x00\x00\x00\x00\x00" \
                     b"\x6a\x8d"
        sock.send(nav_packet)
        _ = sock.recv(1024)
        sock.send(nav_packet)
        _ = sock.recv(1024)
        sock.close()

    def start_test_client_second_nav_incorrect(self):
        sock = socket.socket()
        sock.connect((self.host, self.port))
        auth_packet = b"\x01\x00\x00\x0b\x00\x0f\x00\x01\x00\x01\x06\x08\x00\x01\x00\x38\x01\x01\x05\x05\x00\x00\xef" \
                      b"\x03\x00\x00\x07\xcd"
        sock.send(auth_packet)
        _ = sock.recv(1024)
        nav_packet = b"\x01\x00\x00\x0b\x00\x23\x00\x00\x00\x01\x99\x18\x00\x00\x00\x01\xef\x00\x00\x00\x02\x02\x10" \
                     b"\x15\x00\xd2\x31\x2b\x10\x4f\xba\x3a\x9e\xd2\x27\xbc\x35\x03\x00\x00\xb2\x00\x00\x00\x00\x00" \
                     b"\x6a\x8d"
        sock.send(nav_packet)
        _ = sock.recv(1024)
        incorrect_nav_packet = b"\x01\x00\x00\x0b\x00\x23\x00\x00\x00\x01\x99\x18\x00\x00\x00\x01\xef\x00\x00\x00" \
                               b"\x01\x02\x10\x15\x00\xd2\x31\x2b\x10\x4f\xba\x3a\x9e\xd2\x27\xbc\x35\x03\x00\x00" \
                               b"\xb2\x00\x00\x00\x00\x00\x6a\x8d"
        sock.send(incorrect_nav_packet)
        _ = sock.recv(1024)
        sock.close()

    def start_test_client_only_auth(self):
        sock = socket.socket()
        sock.connect((self.host, self.port))
        auth_packet = b"\x01\x00\x00\x0b\x00\x0f\x00\x01\x00\x01\x06\x08\x00\x01\x00\x38\x01\x01\x05\x05\x00\x00\xef" \
                      b"\x03\x00\x00\x07\xcd"
        sock.send(auth_packet)
        _ = sock.recv(1024)
        sock.close()

    def start_test_client_two_auth(self):
        sock = socket.socket()
        sock.connect((self.host, self.port))
        auth_packet = b"\x01\x00\x00\x0b\x00\x0f\x00\x01\x00\x01\x06\x08\x00\x01\x00\x38\x01\x01\x05\x05\x00\x00" \
                      b"\xef\x03\x00\x00\x07\xcd"
        sock.send(auth_packet)
        _ = sock.recv(1024)
        sock.send(auth_packet)
        sock.close()

    def start_test_first_not_auth(self):
        sock = socket.socket()
        sock.connect((self.host, self.port))
        nav_packet = b"\x01\x00\x00\x0b\x00\x23\x00\x00\x00\x01\x99\x18\x00\x00\x00\x01\xef\x00\x00\x00\x02\x02\x10" \
                     b"\x15\x00\xd2\x31\x2b\x10\x4f\xba\x3a\x9e\xd2\x27\xbc\x35\x03\x00\x00\xb2\x00\x00\x00\x00\x00" \
                     b"\x6a\x8d"
        sock.send(nav_packet)
        _ = sock.recv(1024)
        sock.close()

    def start_test_first_incorrect(self):
        sock = socket.socket()
        sock.connect((self.host, self.port))
        auth_packet = b"\x01\x00\x00\x0b\x00\x1f\x00\x01\x00\x01\x06\x08\x00\x01\x00\x38\x01\x01\x05\x05\x00\x00\xef" \
                      b"\x03\x00\x00\07\xcd"
        sock.send(auth_packet)
        _ = sock.recv(1024)
        sock.close()

    def start_test_nav_incorrect(self):
        sock = socket.socket()
        sock.connect((self.host, self.port))
        auth_packet = b"\x01\x00\x00\x0b\x00\x0f\x00\x01\x00\x01\x06\x08\x00\x01\x00\x38\x01\x01\x05\x05\x00\x00" \
                      b"\xef\x03\x00\x00\x07\xcd"
        sock.send(auth_packet)
        _ = sock.recv(1024)
        nav_packet = b"\x3a\x9e\xd2\x27\xbc\x35\x03\x00\x00\xb2\x00\x00\x00\x00\x00\x6a\x8d"
        sock.send(nav_packet)
        sock.close()

    def _parse_egts(self, data):
        try:
            self.egts = Egts(data)
        except Exception as err:
            self.fail("Error while parsing EGTS:" + str(err))


if __name__ == '__main__':
    unittest.main()
