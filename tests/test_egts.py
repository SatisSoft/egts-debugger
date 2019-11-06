import unittest
from egtsdebugger.egts import *

nav_packet = b"\x01\x00\x00\x0b\x00\x23\x00\x00\x00\x01\x99\x18\x00\x00\x00\x01\xef\x00\x00\x00\x02\x02\x10\x15\x00" \
             b"\xd2\x31\x2b\x10\x4f\xba\x3a\x9e\xd2\x27\xbc\x35\x03\x00\x00\xb2\x00\x00\x00\x00\x00\x6a\x8d"
auth_packet = b"\x01\x00\x00\x0b\x00\x0f\x00\x01\x00\x01\x06\x08\x00\x01\x00\x38\x01\x01\x05\x05\x00\x01\xef\x03\x00" \
              b"\x00\x56\x67"

packet_without_index = b"\x00\x00\x00\x0b\x00\x23\x00\x00\x00\x04\x99\x18\x00\x00\x00\x05\xef\x00\x00\x00\x02\x02\x10" \
                       b"\x15\x00\xd2\x31\x2b\x10\x4f\xba\x3a\x9e\xd2\x27\xbc\x35\x03\x00\x00\xb2\x00\x00\x00\x00\x00" \
                       b"\x6a\x8d"
packet_short_header = b"\x01\x00\x00\x0b\x00"
packet_incorrect_prf = b"\x01\x00\x40\x0b\x00\x23\x00\x00\x00\x04\x99\x18\x00\x00\x00\x05\xef\x00\x00\x00\x02\x02\x10" \
                       b"\x15\x00\xd2\x31\x2b\x10\x4f\xba\x3a\x9e\xd2\x27\xbc\x35\x03\x00\x00\xb2\x00\x00\x00\x00\x00" \
                       b"\x6a\x8d"
packet_incorrect_header_len = b"\x01\x00\x00\x0a\x00\x23\x00\x00\x00\x01\x99\x18\x00\x00\x00\x01\xef\x00\x00\x00\x02" \
                              b"\x02\x10\x15\x00\xd2\x31\x2b\x10\x4f\xba\x3a\x9e\xd2\x27\xbc\x35\x03\x00\x00\xb2\x00" \
                              b"\x00\x00\x00\x00\x6a\x8d"
packet_incorrect_header_crc = b"\x01\x00\x00\x0b\x00\x23\x00\x00\x00\x01\x98\x18\x00\x00\x00\x01\xef\x00\x00\x00\x02" \
                              b"\x02\x10\x15\x00\xd2\x31\x2b\x10\x4f\xba\x3a\x9e\xd2\x27\xbc\x35\x03\x00\x00\xb2\x00" \
                              b"\x00\x00\x00\x00\x6a\x8d"
packet_nill_body = b"\x01\x00\x00\x0b\x00\x00\x00\x00\x00\x01\x25\x18\x00\x00\x00\x01\xef\x00\x00\x00\x02\x02\x10\x15" \
                   b"\x00\xd2\x31\x2b\x10\x4f\xba\x3a\x9e\xd2\x27\xbc\x35\x03\x00\x00\xb2\x00\x00\x00\x00\x00\x6a\x8d"
packet_short_body = b"\x01\x00\x00\x0b\x00\x23\x00\x00\x00\x01\x99\x18\x00\x00\x00\x01\xef\x00\x00\x00\x02"
packet_incorrect_body_crc = b"\x01\x00\x00\x0b\x00\x23\x00\x00\x00\x01\x99\x18\x00\x00\x00\x01\xef\x00\x00\x00\x02" \
                            b"\x02\x10\x15\x00\xd2\x31\x2b\x10\x4f\xba\x3a\x9e\xd2\x27\xbc\x35\x03\x00\x00\xb2\x00" \
                            b"\x00\x00\x00\x00\x6a\x8e"
packet_unknown_packet_type = b"\x01\x00\x00\x0b\x00\x23\x00\x00\x00\x02\xCA\x18\x00\x00\x00\x01\xef\x00\x00\x00\x02" \
                             b"\x02\x10\x15\x00\xd2\x31\x2b\x10\x4f\xba\x3a\x9e\xd2\x27\xbc\x35\x03\x00\x00\xb2\x00" \
                             b"\x00\x00\x00\x00\x6a\x8d"
packet_short_record = b"\x01\x00\x00\x0b\x00\x06\x00\x00\x00\x01\xAD\x18\x00\x00\x00\x00\x01\xf7\x09"
packet_short_record1 = b"\x01\x00\x00\x0b\x00\x08\x00\x00\x00\x01\x1B\x18\x00\x00\x00\x01\x01\x00\x01\xf5\x43"
packet_invalid_record_len = b"\x01\x00\x00\x0b\x00\x23\x00\x00\x00\x01\x99\x21\x00\x00\x00\x01\xef\x00\x00\x00\x02" \
                            b"\x02\x10\x15\x00\xd2\x31\x2b\x10\x4f\xba\x3a\x9e\xd2\x27\xbc\x35\x03\x00\x00\xb2\x00" \
                            b"\x00\x00\x00\x00\x2e\xd7"
packet_short_subrecord_header = b"\x01\x00\x00\x0b\x00\x0d\x00\x00\x00\x01\xD7\x02\x00\x00\x00\x01\xef\x00\x00\x00" \
                                b"\x02\x02\x10\x15\xfd\x22"
packet_short_subrecord_data = b"\x01\x00\x00\x0b\x00\x23\x00\x00\x00\x01\x99\x18\x00\x00\x00\x01\xef\x00\x00\x00\x02" \
                              b"\x02\x10\x16\x00\xd2\x31\x2b\x10\x4f\xba\x3a\x9e\xd2\x27\xbc\x35\x03\x00\x00\xb2\x00" \
                              b"\x00\x00\x00\x00\x77\x22"
packet_unknown_service = b"\x01\x00\x00\x0b\x00\x23\x00\x00\x00\x01\x99\x18\x00\x00\x00\x01\xef\x00\x00\x00\x03\x02" \
                         b"\x10\x15\x00\xd2\x31\x2b\x10\x4f\xba\x3a\x9e\xd2\x27\xbc\x35\x03\x00\x00\xb2\x00\x00\x00" \
                         b"\x00\x00\x0b\x21"

reply_packet = bytes([1, 0, 3, 11, 0, 16, 0, 9, 0, 0, 167, 9, 0, 0, 6, 0, 9, 0, 24, 2, 2, 0, 3, 0, 9, 0, 0, 0, 195])
nav_packet1 = bytes(
    [1, 0, 0, 11, 0, 35, 0, 16, 0, 1, 61, 24, 0, 16, 0, 1, 96, 34, 1, 0, 2, 2, 16, 21, 0, 96, 250, 82, 17, 68, 117, 177,
     158, 200, 196, 154, 53, 2, 0, 0, 85, 0, 0, 0, 0, 0, 78, 229])
reply_packet1 = bytes(
    [1, 0, 3, 11, 0, 16, 0, 16, 0, 0, 23, 16, 0, 0, 6, 0, 16, 0, 24, 2, 2, 0, 3, 0, 16, 0, 0, 163, 171])


class TestEgts(unittest.TestCase):
    """Tests for Egts class"""

    def test_nav_packet(self):
        egts = Egts(nav_packet)
        self.assertEqual(egts.pid, 0)
        self.assertEqual(egts.packet_type, EGTS_PT_APPDATA)
        [record] = egts.records
        self.assertEqual(record.rid, 0)
        self.assertEqual(record.sst, EGTS_TELEDATA_SERVICE)
        self.assertEqual(record.id, 239)
        [subrecord] = record.subrecords
        self.assertEqual(subrecord.type, EGTS_SR_POS_DATA)
        self.assertTrue(subrecord.vld)
        self.assertEqual(subrecord.ntm, 1533570258000)
        self.assertEqual(subrecord.lat, 55.62752532903746)
        self.assertEqual(subrecord.long, 37.782409656276556)
        self.assertEqual(subrecord.speed, 0)
        self.assertEqual(subrecord.dir, 178)
        self.assertEqual(subrecord.busy, 0)
        self.assertEqual(subrecord.src, 0)

    def test_without_index(self):
        with self.assertRaises(EgtsPcUnsProtocol) as error:
            Egts(packet_without_index)
        self.assertEqual(str(error.exception), "Unsupported protocol version (PRV not found)")
        self.assertEqual(error.exception.error_code, EGTS_PC_UNS_PROTOCOL)

    def test_short_header(self):
        with self.assertRaises(EgtsPcInvdatalen) as error:
            Egts(packet_short_header)
        self.assertEqual(str(error.exception), "Incorrect data length (Transport layer)")
        self.assertEqual(error.exception.error_code, EGTS_PC_INVDATALEN)

    def test_incorrect_prf(self):
        with self.assertRaises(EgtsPcUnsProtocol) as error:
            Egts(packet_incorrect_prf)
        self.assertEqual(str(error.exception), "Unsupported protocol version (PRF != 0)")
        self.assertEqual(error.exception.error_code, EGTS_PC_UNS_PROTOCOL)

    def test_incorrect_header_length(self):
        with self.assertRaises(EgtsPcIncHeaderForm) as error:
            Egts(packet_incorrect_header_len)
        self.assertEqual(str(error.exception), "Header structure error (Transport layer)")
        self.assertEqual(error.exception.error_code, EGTS_PC_INC_HEADERFORM)

    def test_incorrect_header_crc(self):
        with self.assertRaises(EgtsPcHeadercrcError) as error:
            Egts(packet_incorrect_header_crc)
        self.assertEqual(str(error.exception), "Header check sum error (Calculated crc: 153, crc in packet: 152)")
        self.assertEqual(error.exception.error_code, EGTS_PC_HEADERCRC_ERROR)

    def test_nill_body(self):
        with self.assertRaises(EgtsParsingError) as error:
            Egts(packet_nill_body)
        self.assertEqual(str(error.exception), "Packet is correct, but body length = 0")
        self.assertEqual(error.exception.error_code, -1)

    def test_short_body(self):
        with self.assertRaises(EgtsPcInvdatalen) as error:
            Egts(packet_short_body)
        self.assertEqual(str(error.exception), "Incorrect data length (Body buffer length is 10; Must be at least 37)")
        self.assertEqual(error.exception.error_code, EGTS_PC_INVDATALEN)

    def test_incorrect_body_crc(self):
        with self.assertRaises(EgtsPcDatacrcError) as error:
            Egts(packet_incorrect_body_crc)
        self.assertEqual(str(error.exception), "Data check sum error (Calculated crc: 36202, crc in packet: 36458)")
        self.assertEqual(error.exception.error_code, EGTS_PC_DATACRC_ERROR)

    def test_unknown_packet_type(self):
        with self.assertRaises(EgtsPcUnsType) as error:
            Egts(packet_unknown_packet_type)
        self.assertEqual(str(error.exception), "Unsupported type (Packet Type 2 is unknown)")
        self.assertEqual(error.exception.error_code, EGTS_PC_UNS_TYPE)

    def test_short_record(self):
        with self.assertRaises(EgtsPcIncHeaderForm) as error:
            Egts(packet_short_record)
        self.assertEqual(str(error.exception),
                         "Header structure error (Record is shorter then EGTS_SERVICE_LAYER_MIN_RECORD_HEADER_LEN)")
        self.assertEqual(error.exception.error_code, EGTS_PC_INC_HEADERFORM)

    def test_short_record1(self):
        with self.assertRaises(EgtsPcIncHeaderForm) as error:
            Egts(packet_short_record1)
        self.assertEqual(str(error.exception),
                         "Header structure error (Record is shorter then EGTS_SERVICE_LAYER_MIN_RECORD_HEADER_LEN + "
                         "opt_len)")
        self.assertEqual(error.exception.error_code, EGTS_PC_INC_HEADERFORM)

    def test_invalid_data_len(self):
        with self.assertRaises(EgtsPcInvdatalen) as error:
            Egts(packet_invalid_record_len)
        self.assertEqual(str(error.exception), "Incorrect data length (Record)")
        self.assertEqual(error.exception.error_code, EGTS_PC_INVDATALEN)

    def test_short_subrecord_header(self):
        with self.assertRaises(EgtsPcInvdatalen) as error:
            Egts(packet_short_subrecord_header)
        self.assertEqual(str(error.exception), "Incorrect data length (Subrecord header)")
        self.assertEqual(error.exception.error_code, EGTS_PC_INVDATALEN)

    def test_short_subrecord_data(self):
        with self.assertRaises(EgtsPcInvdatalen) as error:
            Egts(packet_short_subrecord_data)
        self.assertEqual(str(error.exception), "Incorrect data length (Subrecord data)")
        self.assertEqual(error.exception.error_code, EGTS_PC_INVDATALEN)

    def test_unknown_service(self):
        with self.assertRaises(EgtsPcSrvcUnkn) as error:
            Egts(packet_unknown_service)
        self.assertEqual(str(error.exception), "Unknown service (sst = 3; srt = 16)")
        self.assertEqual(error.exception.error_code, EGTS_PC_SRVC_UNKN)

    def test_auth_packet(self):
        egts = Egts(auth_packet)
        self.assertEqual(egts.packet_type, EGTS_PT_APPDATA)
        [record] = egts.records
        self.assertEqual(record.rid, 1)
        self.assertEqual(record.sst, EGTS_AUTH_SERVICE)
        [subrecord] = record.subrecords
        self.assertEqual(subrecord.type, EGTS_SR_DISPATCHER_IDENTITY)
        self.assertEqual(subrecord.dt, 1)
        self.assertEqual(subrecord.did, 1007)

    def test_response_packet(self):
        egts = Egts(reply_packet)
        self.assertEqual(egts.packet_type, EGTS_PT_RESPONSE)
        self.assertEqual(egts.rpid, 9)
        self.assertEqual(egts.pr, EGTS_PC_OK)
        [record] = egts.records
        self.assertEqual(record.rid, 9)
        self.assertEqual(record.sst, EGTS_TELEDATA_SERVICE)
        [subrecord] = record.subrecords
        self.assertEqual(subrecord.type, EGTS_PT_RESPONSE)
        self.assertEqual(subrecord.crn, 9)
        self.assertEqual(subrecord.rst, EGTS_PC_OK)

    def test_reply_and_parse_reply(self):
        egts = Egts(nav_packet)
        pid = egts.pid
        self.assertEqual(egts.packet_type, EGTS_PT_APPDATA)
        [record] = egts.records
        rec_num = record.rid
        service = record.sst
        ans_pid, ans_rid = 15, 47
        reply = egts.reply(ans_pid, ans_rid)
        egts_reply = Egts(reply)
        self.assertEqual(egts_reply.packet_type, EGTS_PT_RESPONSE)
        self.assertEqual(egts_reply.rpid, pid)
        self.assertEqual(egts_reply.pr, EGTS_PC_OK)
        [reply_record] = egts_reply.records
        self.assertEqual(reply_record.rid, ans_rid)
        self.assertEqual(reply_record.sst, service)
        [reply_subrecord] = reply_record.subrecords
        self.assertEqual(reply_subrecord.type, EGTS_PT_RESPONSE)
        self.assertEqual(reply_subrecord.crn, rec_num)
        self.assertEqual(reply_subrecord.rst, EGTS_PC_OK)

    def test_reply_nav(self):
        egts = Egts(nav_packet1)
        [record] = egts.records
        reply = egts.reply(egts.pid, record.rid)
        self.assertEqual(reply, reply_packet1)

if __name__ == '__main__':
    unittest.main()
