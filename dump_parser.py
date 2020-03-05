#! /usr/bin/env python3.6
# -*- coding: utf-8 -*-

import argparse
import logging
from egtsdebugger.egts import *

if __name__ == "__main__":

  parser = argparse.ArgumentParser()
  parser.add_argument("-f", "--file", help="file with data", required=True)
  args = parser.parse_args()


  f = open(args.file, "rb")
  buff = f.read()

  start = buff.find(b'\x01\x00\x03\x0b')
  if start < 0:
    logging.error("EGTS packets not found: %s", buff)
    buff = b''
  elif start != 0:
    logging.error("First EGTS packet incomplete: %s", buff[:start])
    buff = buff[start:]  

  while len(buff) > 0:
    egts = Egts(buff)
    print(egts)
    buff = egts.rest_buff
