from egtsdebugger.general_server_debugger import *


class ActiveEgtsServerDebugger(GeneralEgtsServerDebugger):
    """Provides functional for testing EGTS server which initiates connection to EGTS client"""

    def _start_client(self):
        s = socket.socket()
        s.connect((self.host, self.port))
        with s:
            try:
                self._send_receive_loop(s)
                self._receive_loop(s)
                self._compare_got_replies_with_expected()
            except EgtsParsingError as err:
                print("ERROR. EGTS connection test failed: error parsing EGTS packet. Error code {0}. {1}.".format(
                    err.error_code, err))
            except IncorrectFirstPacket:
                print("ERROR. First packet is incorrect.")
            except ReceivedNoData:
                print("ERROR. Sent {0} packets including {1} records, but received no replies from EGTS "
                      "server.".format(self.pid, self.rid))
            except socket.error as err:
                print("ERROR. Got socket error:", err)
            except Exception as err:
                print("ERROR. Got unknown error", err)
            finally:
                s.close()

    def _expected_replies(self):
        return list(range(0, len(self.test_data)))

    def _print_success_message(self):
        print("SUCCESS. EGTS connection test succeeded. Sent", self.pid, "packets including", self.rid,
              "records.", "Confirmation for all records were received.")
