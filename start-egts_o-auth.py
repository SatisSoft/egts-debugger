#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import socket
from egtsdebugger.egts import *

if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument("-p", "--port", default=9090, help="listening port")
  parser.add_argument("--hostname", default='localhost', help="hostname")
  parser.add_argument("-d", "--dispatcher", default=0, help="dispatcher id")
  args = parser.parse_args()

  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    pid = rid = 0
    s.connect((args.hostname, int(args.port)))

    packet_auth = Egts.form_bin(pid, [
      EgtsRecord(rid=rid, sst=1, subrecords=[
        EgtsSrDispatcherIdentity(5, dt=0, did=int(args.dispatcher))])])

    num = s.send(packet_auth)

    buffer = s.recv(1024)
    while len(buffer) > 0:
      egts = Egts(buffer)
      if egts.packet_type == 1:
        pid += 1
        rid += 1
        s.send(egts.reply(1, 1))
      print(egts)
      buffer = egts.rest_buff
