from server_debugger import EgtsServerDebugger
import argparse


def port_type(x):
    x = int(x)
    if x < 1024 or x > 65535:
        raise argparse.ArgumentTypeError("Port number must be between 1024 and 65535")
    return x


def n_type(x):
    x = int(x)
    if x <= 1:
        raise argparse.ArgumentTypeError("The number of packets must be grater then 1")
    return x


parser = argparse.ArgumentParser()
parser.add_argument("-p", "--port", default=9090, type=port_type, help="listening port")
parser.add_argument("--hostname", default='', help="hostname")
parser.add_argument("-n", "--number", default=10, type=n_type,
                    help="number of packets to receive before finish the debugger")
parser.add_argument("-d", "--dispatcher", default=-1, type=int, help="dispatcher id")
args = parser.parse_args()

egts_conn_test = EgtsServerDebugger(args.hostname, args.port, args.number, args.dispatcher)
egts_conn_test.start_listening()
