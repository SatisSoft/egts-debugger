from egtsdebugger.script_argument_parser import *
from egtsdebugger.active_server_debugger import ActiveEgtsServerDebugger

parser = argparse.ArgumentParser()
parser.add_argument("-p", "--port", default=9090, type=port_type, help="listening port")
parser.add_argument("--hostname", default='', help="hostname")
parser.add_argument("--data", default="data/test.csv", help="file with test data")
args = parser.parse_args()

egts_client_test = ActiveEgtsServerDebugger(args.hostname, args.port, args.data)
egts_client_test.start()
