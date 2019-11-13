from egtsdebugger.general_server_debugger import *


class PassiveEgtsServerDebugger(GeneralEgtsServerDebugger):
    """Provides functional for testing a EGTS server which initiates connection with the EGTS client"""

    def _start_client(self):
        s = socket.socket()
        s.bind((self.host, self.port))
        s.listen(1)
        conn, addr = s.accept()
        with conn:
            data = conn.recv(1024)
            if not data:
                print("ERROR. server has closed the connection. No packets were received.")
                s.close()
                return
            try:
                egts = self._validate_first_packet(data)
                reply = egts.reply(self.pid, self.rid)
                conn.send(reply)
                self.pid += 1
                self.rid += 1
                self._send_receive_loop(conn)
                self._receive_loop(conn)
                self._compare_got_replies_with_expected()
            except EgtsParsingError as err:
                print("ERROR. EGTS connection test failed: error parsing EGTS packet. Error code {0}. {1}.".format(
                    err.error_code, err))
            except IncorrectFirstPacket:
                print("ERROR. First packet is incorrect.")
            except ReceivedNoData:
                print("ERROR. Sent {0} packets including {1} records, but received no replies from EGTS "
                      "server.".format(self.pid - 1, self.rid - 1))
            except socket.error as err:
                print("ERROR. Got socket error:", err)
            except Exception as err:
                print("ERROR. Got unknown error", err)
            finally:
                s.close()