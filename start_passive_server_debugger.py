from egtsdebugger.script_argument_parser import *
from egtsdebugger.passive_server_debugger import PassiveEgtsServerDebugger

parser = argparse.ArgumentParser()
parser.add_argument("-p", "--port", default=9090, type=port_type, help="listening port")
parser.add_argument("--hostname", default='', help="hostname")
parser.add_argument("--data", default="data/2000_records.csv", help="file with test data")
parser.add_argument("-d", "--dispatcher", default=999, help="dispatcher id", type=d_type)

args = parser.parse_args()

egts_client_test = PassiveEgtsServerDebugger(args.hostname, args.port, args.data, args.dispatcher)
egts_client_test.start()
