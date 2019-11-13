import socket
import threading
import time
import unittest
import sys
from io import StringIO

from egtsdebugger.active_server_debugger import ActiveEgtsServerDebugger
from egtsdebugger.egts import *

auth_packet = b"\x01\x00\x00\x0b\x00\x0f\x00\x01\x00\x01\x06\x08\x00\x01\x00\x38\x01\x01\x05\x05\x00\x00\xef" \
              b"\x03\x00\x00\x07\xcd"
incorrect_reply = bytes([1, 0, 3, 11, 0, 16, 0, 9, 0, 0, 167, 9, 0, 0, 6, 0, 9, 0, 24, 2, 2, 0, 3, 0, 9, 0, 0, 0, 196])
reply_packet = bytes([1, 0, 3, 11, 0, 16, 0, 9, 0, 0, 167, 9, 0, 0, 6, 0, 9, 0, 24, 2, 2, 0, 3, 0, 9, 0, 0, 0, 195])

class TestActiveServerDebugger(unittest.TestCase):
    """Tests for EgtsActiveServerDebugger class"""

    def setUp(self):
        self.port = 9093
        self.host = 'localhost'
        self.num = 10
        self.dispatcher = 1007
        self.filename = '../data/2000_records.csv'

    def test_connection_error(self):
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        sever_thread = self.start_debugger_thread()
        self.start_test_server_connection_error()
        sever_thread.join()
        output = mystdout.getvalue()
        sys.stdout = old_stdout
        msg = "ERROR. Got socket error:"
        self.assertEqual(output.startswith(msg), True)

    def test_incorrect_first_message(self):
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        sever_thread = self.start_debugger_thread()
        self.start_test_server_incorrect_first_message()
        sever_thread.join()
        output = mystdout.getvalue()
        sys.stdout = old_stdout
        self.assertEqual("ERROR. EGTS connection test failed: error parsing EGTS packet. Error code 128. Unsupported "
                         "protocol version (PRV not found).\n",
                         output)

    def test_success_1(self):
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        sever_thread = self.start_debugger_thread(**{'filename': "../data/1_record.csv"})
        self.start_test_server_success(1)
        sever_thread.join()
        output = mystdout.getvalue()
        sys.stdout = old_stdout
        msg = "SUCCESS. EGTS connection test succeeded. Sent 1 packets including 1 records. Confirmation for all " \
              "records were received.\n"
        self.assertEqual(msg, output)

    def test_success_5(self):
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        sever_thread = self.start_debugger_thread(**{'filename': "../data/5_records.csv"})
        self.start_test_server_success(1)
        sever_thread.join()
        output = mystdout.getvalue()
        sys.stdout = old_stdout
        msg = "SUCCESS. EGTS connection test succeeded. Sent 1 packets including 5 records. Confirmation for all " \
              "records were received.\n"
        self.assertEqual(msg, output)

    def test_success_2000(self):
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        sever_thread = self.start_debugger_thread()
        self.start_test_server_success(20)
        sever_thread.join()
        output = mystdout.getvalue()
        sys.stdout = old_stdout
        msg = "SUCCESS. EGTS connection test succeeded. Sent 20 packets including 2000 records. Confirmation for all " \
              "records were received.\n"
        self.assertEqual(msg, output)

    def test_incorrect_egts_reply(self):
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        sever_thread = self.start_debugger_thread()
        self.start_test_incorrect_egts_reply()
        sever_thread.join()
        output = mystdout.getvalue()
        sys.stdout = old_stdout
        msg = "ERROR. EGTS connection test failed: error parsing EGTS packet. Error code 138. Data check sum error (" \
              "Calculated crc: 49920, crc in packet: 50176).\n"
        self.assertEqual(msg, output)

    def test_unexpected_reply_success(self):
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        sever_thread = self.start_debugger_thread(**{'filename': "../data/5_records.csv"})
        self.start_test_unexpected_reply_success()
        sever_thread.join()
        output = mystdout.getvalue()
        sys.stdout = old_stdout
        msg = """Warning: received unexpected replies: [9]
SUCCESS. EGTS connection test succeeded. Sent 1 packets including 5 records. Confirmation for all records were received.
"""
        self.assertEqual(msg, output)

    def test_unexpected_reply_failed(self):
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        sever_thread = self.start_debugger_thread(**{'filename': "../data/5_records.csv"})
        self.start_test_unexpected_reply_failed()
        sever_thread.join()
        output = mystdout.getvalue()
        sys.stdout = old_stdout
        msg = """Warning: received unexpected replies: [9]
Error: did't receive reply on packets [0, 1, 2, 3, 4]
"""
        self.assertEqual(msg, output)

    def test_did_not_received_replies(self):
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        sever_thread = self.start_debugger_thread(**{'filename': "../data/5_records.csv"})
        self.start_test_did_not_received_replies()
        sever_thread.join()
        output = mystdout.getvalue()
        sys.stdout = old_stdout
        msg = "ERROR. Sent 1 packets including 5 records, but received no replies from EGTS server.\n"
        self.assertEqual(msg, output)

    def test_socket_error(self):
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        sever_thread = self.start_debugger_thread(**{'filename': "../data/2000_records.csv"})
        self.start_test_socket_error()
        sever_thread.join()
        output = mystdout.getvalue()
        sys.stdout = old_stdout
        msg = "ERROR. Got socket error:"
        self.assertEqual(output.startswith(msg), True)


    def start_debugger_thread(self, **kwargs):
        if 'filename' in kwargs:
            filename = kwargs['filename']
        else:
            filename = self.filename
        egts_conn_test = ActiveEgtsServerDebugger(self.host, self.port, self.num, filename, self.dispatcher)
        debug_thread = threading.Thread(target=egts_conn_test.start)
        debug_thread.start()
        return debug_thread

    def start_test_server_connection_error(self):
        sock = socket.socket()
        sock.bind((self.host, self.port))
        sock.listen(1)
        conn, _  = sock.accept()
        conn.close()
        sock.close()

    def start_test_server_incorrect_first_message(self):
        sock = socket.socket()
        sock.bind((self.host, self.port))
        sock.listen(1)
        conn, addr = sock.accept()
        msg = bytes(555)
        conn.send(msg)
        conn.close()
        sock.close()

    def start_test_server_success(self, num_of_packets):
        sock = socket.socket()
        sock.bind((self.host, self.port))
        sock.listen(1)
        conn, addr = sock.accept()
        buff = b""
        pid = 0
        rid = 0
        with conn:
            while pid < num_of_packets:
                data = conn.recv(1024)
                buff = buff + data
                try:
                    while len(buff) > 0:
                        egts = Egts(buff)
                        buff = egts.rest_buff
                        reply = egts.reply(pid, rid)
                        pid += 1
                        rid += 1
                        conn.send(reply)
                except EgtsParsingError:
                    continue
                finally:
                    sock.close()

    def start_test_incorrect_egts_reply(self):
        sock = socket.socket()
        sock.bind((self.host, self.port))
        sock.listen(1)
        conn, addr = sock.accept()
        conn.recv(1024)
        conn.send(incorrect_reply)
        time.sleep(0.0001)
        conn.close()
        sock.close()

    def start_test_unexpected_reply_success(self):
        sock = socket.socket()
        sock.bind((self.host, self.port))
        sock.listen(1)
        conn, addr = sock.accept()
        data = conn.recv(1024)
        egts = Egts(data)
        reply = egts.reply(1, 1)
        conn.send(reply_packet)
        conn.send(reply)
        conn.close()
        sock.close()

    def start_test_unexpected_reply_failed(self):
        sock = socket.socket()
        sock.bind((self.host, self.port))
        sock.listen(1)
        conn, addr = sock.accept()
        conn.recv(1024)
        conn.send(reply_packet)
        conn.close()
        sock.close()

    def start_test_did_not_received_replies(self):
        sock = socket.socket()
        sock.bind((self.host, self.port))
        sock.listen(1)
        conn, addr = sock.accept()
        conn.recv(1024)
        conn.close()
        sock.close()

    def start_test_socket_error(self):
        sock = socket.socket()
        sock.bind((self.host, self.port))
        sock.listen(1)
        conn, addr = sock.accept()
        conn.close()
        sock.close()


    def _parse_egts(self, data):
        try:
            self.egts = Egts(data)
        except Exception as err:
            self.fail("Error while parsing EGTS:" + str(err))

if __name__ == '__main__':
    unittest.main()
