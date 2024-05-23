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


def d_type(x):
    try:
        x = int(x)
        if x < 0 or x > 0xFFffFFff:
            raise ValueError
    except ValueError:
        raise argparse.ArgumentTypeError("Dispatcher ID must be between 0 and 4294967295") from None
    return x
