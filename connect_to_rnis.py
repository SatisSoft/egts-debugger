from rnis_connector import RnisConnector
import argparse

def port_type(x):
    x = int(x)
    if x < 1024 or x > 65535:
        raise argparse.ArgumentTypeError("Port number must be between 1024 and 65535")
    return x


def n_type(x):
    x = int(x)
    if x < 1:
        raise argparse.ArgumentTypeError("The number of packets must be grater then 0")
    return x


parser = argparse.ArgumentParser()
parser.add_argument("-p", "--port", default=9090, type=port_type, help="listening port")
parser.add_argument("-f", "--file", default="result.log", help="file to write logs")
parser.add_argument("--hostname", default='', help="hostname")
parser.add_argument("-n", "--number", default=10, type=n_type,
                    help="number of packets to receive before finish the debugger")
parser.add_argument("-d", "--dispatcher", default=0, type=int, help="dispatcher id")
group = parser.add_argument_group('auth', 'should be used without dispatcher id')
group.add_argument("--login", type=str, help="login")
group.add_argument("--password", type=str, help="password")

args = parser.parse_args()

if not args.dispatcher and args.login and args.password:
    dispatcher = 0xFFffFFff
elif args.dispatcher and not (args.login or args.password):
    dispatcher = args.dispatcher
else:
    parser.print_help()
    exit(1)


rnis_connector = RnisConnector(args.hostname,
                               args.port,
                               args.number,
                               dispatcher,
                               args.file,
                               login=args.login,
                               password=args.password)
rnis_connector.start()
