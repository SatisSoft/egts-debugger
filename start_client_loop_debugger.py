from egtsdebugger.client_debugger import EgtsClientDebugger
from egtsdebugger.script_argument_parser import *
import logging

parser = argparse.ArgumentParser()
parser.add_argument("-p", "--port", default=9090, type=port_type, help="listening port")
parser.add_argument("--hostname", default='', help="hostname")
parser.add_argument("-d", "--dispatcher", default=-1, type=n_type, help="dispatcher id")
args = parser.parse_args()

# Logfmt format
logging.basicConfig(
  format = ' '.join([
    'time=%(asctime)s',
    'level=%(levelname)s',
    'logger=%(module)s',
    'msg="%(message)s"',
    'filename="%(filename)s"',
    'line=%(lineno)d'
  ]),
  level = logging.INFO,
  datefmt="%Y-%m-%dT%H:%M:%SZ",
)

INFINITE = -1

egts_conn_test = EgtsClientDebugger(args.hostname, args.port, INFINITE, args.dispatcher)
egts_conn_test.start_listening(accept_loop=True)
