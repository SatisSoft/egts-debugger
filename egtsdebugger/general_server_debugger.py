import socket
import csv
import time

from egtsdebugger.egts import *

class IncorrectNumberOfDispIdentity(ValueError):
    pass

class IncorrectFirstPacket(ValueError):
    pass

class UnexpectedDispatcherIdentity(ValueError):
    pass

class ReceivedNoData(ValueError):
    pass

class ErrorSendingToServer(ValueError):
    pass

class ErrorReceivingFromClient(ValueError):
    pass


class GeneralEgtsServerDebugger:
    """Provides functional for testing EGTS server"""

    def __init__(self, host, port, filename):
        self.host = host
        self.port = port
        self.pid = 0
        self.rid = 0
        self.filename = filename
        self.test_data = []
        self.buff = b''
        self.expected_replies = []
        self.got_replies = []
        self.received_replies = []

    def start(self):
        self.test_data = self._parse_test_data()
        if len(self.test_data) == 0:
            print("ERROR. File with data is empty")
            return
        self.expected_replies = self._expected_replies()
        self._start_client()

    def _start_client(self):
        pass

    def _send_receive_loop(self, conn):
        len_of_data = len(self.test_data)
        rid_on_start = self.rid
        last_rid = rid_on_start + len_of_data
        while self.rid < last_rid:
                if self.rid + 100 > len_of_data:
                    packet = self._form_packet(last_rid, rid_on_start)
                else:
                    packet = self._form_packet(self.rid + 100 + rid_on_start, rid_on_start)
                conn.send(packet)
                replies = conn.recv(1024)
                if not replies:
                    raise ReceivedNoData
                self._parse_replies(replies)



    def _receive_loop(self, conn):
        expected_replies_len = len(self.expected_replies)
        start = time.time()
        with conn:
            while len(self.got_replies) != expected_replies_len:
                conn.settimeout(1)
                if expected_replies_len == len(self.got_replies):
                    return
                now = time.time()
                if int(now - start) > 1:
                    return
                replies = conn.recv(1024)
                self._parse_replies(replies)

    def _parse_replies(self, replies):
        packets = self._parse_packets(self.buff + replies)
        self._get_approved_ids(packets)

    def _form_packet(self, end, rid_on_start):
        records = []
        while self.rid < end:
            data = self.test_data[self.rid-rid_on_start]
            subrecords = [self._dict_to_subrecord(data)]
            records.append(self._make_record(data['id'], subrecords))
            self.rid += 1
        packet = Egts.form_bin(self.pid, records)
        self.pid += 1
        return packet

    def _expected_replies(self):
        return list(range(1, len(self.test_data) + 1))

    def _parse_test_data(self):
        with open(self.filename) as csv_file:
            csv_reader = csv.DictReader(csv_file)
            result = []
            for row in csv_reader:
                row["time"] = int(row["time"])
                row["id"] = int(row["id"])
                row["lat"] = float(row["lat"])
                row["lon"] = float(row["lon"])
                row["speed"] = float(row["speed"])
                row["bearing"] = float(row["bearing"])
                row["order"] = int(row["order"])
                result.append(row)
            return result

    @staticmethod
    def _dict_to_subrecord(data):
        kwargs = {'vld': 1, 'ntm': data["time"], 'lat': data["lat"], 'lon': data["lon"], 'speed': data["speed"],
                  'dir': data["bearing"], 'busy': data["order"], 'src': 0, 'mv': 0, 'bb': 0}
        return EgtsSrPosData(**kwargs)

    def _make_record(self, terminal_id, subrecords):
        kwargs = {'id': terminal_id, 'subrecords': subrecords, 'num': self.rid, 'sst': EGTS_TELEDATA_SERVICE,
                  'rid': self.rid}
        return EgtsRecord(**kwargs)

    @staticmethod
    def _parse_packets(buff):
        packets = []
        while len(buff) > 0:
            try:
                egts = Egts(buff)
                buff = egts.rest_buff
                packets.append(egts)
            except EgtsPcInvdatalen as err:
                if len(buff) > 2048:
                    print("Error parsing packet:", err, buff)
                break
        return packets

    def _get_approved_ids(self, packets):
        for packet in packets:
            if self._validate_responce_packet(packet):
                self._analyze_records(packet.records)
            else:
                continue

    @staticmethod
    def _validate_responce_packet(packet):
        if packet.packet_type != EGTS_PT_RESPONSE:
            print("Warning: expected EGTS_PT_RESPONSE packet but got {0}".format(packet))
            return False
        if packet.pr != EGTS_PC_OK:
            print("Warning: received EGTS_PT_RESPONSE packet {0} with error process_result {1}".format(packet,
                                                                                                       packet.pr))
            return False
        return True

    def _analyze_records(self, records):
        for record in records:
            self._analyze_subrecords(record.subrecords)

    def _analyze_subrecords(self, subrecords):
        for subrecord in subrecords:
            if type(subrecord) is not EgtsResponse:
                print("Error: expected Egts Responce subrecord but got {0}".format(subrecord))
            if subrecord.rst != EGTS_PC_OK:
                print("Warning: received subrecord {0} in EGTS_PT_RESPONSE packet with error record status".format(
                    subrecord.subrecord_to_string()))
                continue
            self.got_replies.append(subrecord.crn)

    def _compare_got_replies_with_expected(self):
        missed_results = [rec for rec in self.expected_replies if rec not in self.got_replies]
        unexpected_replies = [rec for rec in self.got_replies if rec not in self.expected_replies]
        if len(unexpected_replies) != 0:
            print("Warning: received unexpected replies: {0}".format(unexpected_replies))
        if len(missed_results) != 0:
            print("Error: did't receive reply on packets {0}".format(missed_results))
        else:
            self._print_success_message()

    def _print_success_message(self):
        print("SUCCESS. EGTS connection test succeeded. Sent", self.pid-1, "packets including", self.rid-1,
              "records.", "Confirmation for all records were received.")

    def _validate_first_packet(self, data):
        egts = Egts(data)
        if self.dispatcher < 0:
            subs = self._found_dispatcher_identity(egts.records)
            if len(subs) > 1:
                print("Error validating first packet:", egts)
                raise IncorrectNumberOfDispIdentity
            elif len(subs) == 1:
                [sub] = subs
                if not self._validate_dispatcher_identity_sub(sub, 1):
                    raise UnexpectedDispatcherIdentity
            print("Received auth packet from:", egts)
        else:
            subs = self._found_dispatcher_identity(egts.records)
            if len(subs) == 1:
                [sub] = subs
                if self._validate_dispatcher_identity_sub(sub, self.dispatcher):
                    print("First packet is correct:", egts)
                    return egts
                else:
                    print("Error validating first packet:", egts)
                    raise IncorrectFirstPacket
            else:
                print("Error validating first packet:", egts)
                raise IncorrectNumberOfDispIdentity
        return egts

    @staticmethod
    def _found_dispatcher_identity(records):
        subs = []
        for record in records:
            for sub in record.subrecords:
                if type(sub) is EgtsSrDispatcherIdentity:
                    subs.append(sub)
        return subs

    @staticmethod
    def _validate_dispatcher_identity_sub(sub, did):
        if sub.dt != 0:
            print("Dispatcher Type must be equal to 0. Currently it is equal to", sub.dt)
            return False
        if sub.did != did:
            print("Expected Dispatcher ID =", did, "but got", sub.did)
            return False
        return True
