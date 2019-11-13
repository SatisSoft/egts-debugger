from egtsdebugger.client_debugger import EgtsClientDebugger
from egtsdebugger.script_argument_parser import *

parser = argparse.ArgumentParser()
parser.add_argument("-p", "--port", default=9090, type=port_type, help="listening port")
parser.add_argument("--hostname", default='', help="hostname")
parser.add_argument("-n", "--number", default=10, type=n_type,
                    help="number of packets to receive before finish the debugger")
parser.add_argument("-d", "--dispatcher", default=-1, help="dispatcher id")
args = parser.parse_args()

egts_conn_test = EgtsClientDebugger(args.hostname, args.port, args.number, args.dispatcher)
egts_conn_test.start_listening()
