import crcmod

EGTS_PROTOCOL_VERSION = b'\x01'
EGTS_PC_OK = 0
EGTS_TRANSPORT_LAYER_MIN_HEADER_LEN = 11
EGTS_SERVICE_LAYER_MIN_RECORD_HEADER_LEN = 7
EGTS_SERVICE_LAYER_MIN_SUBRECORD_LEN = 3
# polynomial are taken from EGTS documentation
# x^8 + x^5 + x^4 + 1 = 0x0131
crc8_func = crcmod.mkCrcFun(0x0131, initCrc=0xFF, rev=False)
# x^16 + x^12 + x^5 + 1 = 0x011021
crc16_func = crcmod.mkCrcFun(0x011021, initCrc=0xFFFF, rev=False)
EGTS_PT_RESPONSE = 0
EGTS_PT_APPDATA = 1
timestamp_20100101_000000_utc = 1262304000
EGTS_AUTH_SERVICE = 1
EGTS_TELEDATA_SERVICE = 2
EGTS_SR_DISPATCHER_IDENTITY = 5
EGTS_SR_POS_DATA = 16

EGTS_SR_DISPATCHER_IDENTITY_DESCR = "EGTS_SR_DISPATCHER_IDENTITY"

EGTS_PC_UNS_PROTOCOL = 128
EGTS_PC_UNS_PROTOCOL_DESCR = "Unsupported protocol version"
EGTS_PC_INC_HEADERFORM = 131
EGTS_PC_INC_HEADERFORM_DESCR = "Header structure error"

EGTS_PC_UNS_TYPE = 133
EGTS_PC_UNS_TYPE_DESCR = "Unsupported type"
EGTS_PC_HEADERCRC_ERROR = 137
EGTS_PC_HEADERCRC_ERROR_DESCR = "Header check sum error"
EGTS_PC_DATACRC_ERROR = 138
EGTS_PC_DATACRC_ERROR_DESCR = "Data check sum error"
EGTS_PC_SRVC_UNKN = 150
EGTS_PC_SRVC_UNKN_DESCR = "Unknown service"
EGTS_PC_INVDATALEN = 139
EGTS_PC_INVDATALEN_DESCR = "Incorrect data length"
EGTS_PC_SR_UNKN = 165
EGTS_PC_SR_UNKN_DESCR = "Unknown service subrecord type"


class EgtsParsingError(ValueError):
    def __init__(self, message, error_description, error_code):
        if message:
            error_description += " ({0})".format(message)
        super().__init__(error_description)
        self.error_code = error_code


class EgtsPcUnsProtocol(EgtsParsingError):
    def __init__(self, message=""):
        super().__init__(message, EGTS_PC_UNS_PROTOCOL_DESCR, EGTS_PC_UNS_PROTOCOL)


class EgtsPcIncHeaderForm(EgtsParsingError):
    def __init__(self, message=""):
        super().__init__(message, EGTS_PC_INC_HEADERFORM_DESCR, EGTS_PC_INC_HEADERFORM)


class EgtsPcUnsType(EgtsParsingError):
    def __init__(self, message=""):
        super().__init__(message, EGTS_PC_UNS_TYPE_DESCR, EGTS_PC_UNS_TYPE)


class EgtsPcHeadercrcError(EgtsParsingError):
    def __init__(self, message=""):
        super().__init__(message, EGTS_PC_HEADERCRC_ERROR_DESCR, EGTS_PC_HEADERCRC_ERROR)


class EgtsPcDatacrcError(EgtsParsingError):
    def __init__(self, message=""):
        super().__init__(message, EGTS_PC_DATACRC_ERROR_DESCR, EGTS_PC_DATACRC_ERROR)


class EgtsPcSrvcUnkn(EgtsParsingError):
    def __init__(self, message=""):
        super().__init__(message, EGTS_PC_SRVC_UNKN_DESCR, EGTS_PC_SRVC_UNKN)


class EgtsPcInvdatalen(EgtsParsingError):
    def __init__(self, message=""):
        super().__init__(message, EGTS_PC_INVDATALEN_DESCR, EGTS_PC_INVDATALEN)


class EgtsPcSrUnkn(EgtsParsingError):
    def __init__(self, message=""):
        super().__init__(message, EGTS_PC_SR_UNKN_DESCR, EGTS_PC_SR_UNKN)


class Egts:
    """Contains information about EGTS packet"""

    def __init__(self, buffer):
        index = self._index(buffer)
        self._proc_transport_layer(buffer[index:])
        self._proc_service_layer(buffer[index + self.header_len:])
        self.rest_buff = buffer[index + self.header_len + len(self.body)+2:]

    @staticmethod
    def form_bin(pid, data):
        body = Egts._body_bin(data)
        packet = Egts._packet_bin(pid, body)
        return packet

    def reply(self, ans_pid, ans_rid):
        subrecords = self._reply_record()
        pack_id = self.pid.to_bytes(2, 'little')
        body = pack_id + b'\x00' + Egts._make_record(self.service, ans_rid, subrecords)
        reply = self._packet_bin(ans_pid, body)
        return reply

    def _proc_transport_layer(self, buffer):
        if len(buffer) < EGTS_TRANSPORT_LAYER_MIN_HEADER_LEN:
            raise EgtsPcInvdatalen("Transport layer")
        if buffer[2] >> 6 != 0:
            raise EgtsPcUnsProtocol("PRF != 0")
        self.header_len = buffer[3]
        if self.header_len != EGTS_TRANSPORT_LAYER_MIN_HEADER_LEN:
            raise EgtsPcIncHeaderForm("Transport layer")
        header = buffer[:self.header_len]
        header_crc = header[-1]
        header_crc_calc = crc8_func(header[:-1])
        if header_crc != header_crc_calc:
            msg = "Calculated crc: {0}, crc in packet: {1}".format(header_crc_calc, header_crc)
            raise EgtsPcHeadercrcError(msg)
        self.body_len = int.from_bytes(header[5:7], byteorder='little')
        self.pid = int.from_bytes(header[7:9], byteorder='little')
        self.packet_type = header[9]

    def _proc_service_layer(self, buffer):
        if self.body_len == 0:
            raise EgtsParsingError("", "Packet is correct, but body length = 0", -1)
        if len(buffer) < self.body_len + 2:
            msg = "Body buffer length is {0}; Must be at least {1}".format(len(buffer), self.body_len + 2)
            raise EgtsPcInvdatalen(msg)
        self.body = buffer[:self.body_len]
        body_crc = int.from_bytes(buffer[self.body_len:self.body_len+2], byteorder='little')
        body_crc_calc = crc16_func(self.body)
        if body_crc != body_crc_calc:
            msg = "Calculated crc: {0}, crc in packet: {1}".format(body_crc_calc, body_crc)
            raise EgtsPcDatacrcError(msg)
        if self.packet_type == EGTS_PT_APPDATA:
            self._parse_appdata()
        elif self.packet_type == EGTS_PT_RESPONSE:
            self._parse_response()
        else:
            raise EgtsPcUnsType("Packet Type " + str(self.packet_type) + " is unknown")

    def _parse_appdata(self):
        self.records = []
        rest_buf = self.body
        while len(rest_buf) > 0:
            rec = EgtsRecord.parse(rest_buf)
            self.records.append(rec)
            rest_buf = rest_buf[rec.rec_len:]
        if self.records:
            rec = self.records[0]
            self.service = rec.sst

    def _parse_response(self):
        if len(self.body) > 3:
            self.rpid = int.from_bytes(self.body[0:2], byteorder='little')
            self.pr = self.body[2]
            self.records = []
            rest_buf = self.body[3:]
            while len(rest_buf) > 0:
                rec = EgtsRecord.parse(rest_buf)
                self.records.append(rec)
                rest_buf = rest_buf[rec.rec_len:]
            if self.records:
                rec = self.records[0]
                self.service = rec.sst
        else:
            raise EgtsPcInvdatalen("Response SFRD")

    @staticmethod
    def _packet_bin(ans_pid, body):
        bcs = crc16_func(body)
        data_len = len(body)
        header = Egts._make_header(ans_pid, data_len)
        hcs = crc8_func(header)
        bcs_bin = bcs.to_bytes(2, 'little')
        reply = header + bytes([hcs]) + body + bcs_bin
        return reply

    @staticmethod
    def _index(buffer):
        try:
            return buffer.index(EGTS_PROTOCOL_VERSION)
        except ValueError:
            raise EgtsPcUnsProtocol("PRV not found")

    def _get_data(self):
        records = []
        for record in self.records:
            subrecords = record.subrecords
            records.append(subrecords)
        return records

    def _reply_record(self):
        res = b""
        for record in self.records:
            rec_id = record.rid
            reply_subrec = bytes([0x00, 0x03, 0x00, rec_id % 256, rec_id//256, 0])
            res += reply_subrec
        return res

    @staticmethod
    def _body_bin(data):
        res = b""
        for rec in data:
            record = rec.form_bin(rec)
            res += record
        return res

    @staticmethod
    def _make_header(ans_pid, data_len):
        rec_len = data_len.to_bytes(2, 'little')
        ans_rid_bin = ans_pid.to_bytes(2, 'little')
        header = b'\x01\x00\x03\x0b\x00' + rec_len + ans_rid_bin + bytes([EGTS_PT_RESPONSE])
        return header

    @staticmethod
    def _make_record(service, ans_rid, subrecords):
        sub_len = len(subrecords).to_bytes(2, 'little')
        rid = ans_rid.to_bytes(2, 'little')
        body = sub_len + rid + b'\x18' + bytes([service]) + bytes([service]) + subrecords
        return body

    def __str__(self):
        s = "Packet ID: {0}; Packet Type: {1}; ".format(self.pid, self.packet_type)
        if self.packet_type == EGTS_PT_RESPONSE:
            s += "Response Packet ID: {0}; Processing Result: {1}; ".format(self.rpid, self.pr)
        records = self._records_2_string()
        s += "records: [{0}]".format(records)
        return s

    def _records_2_string(self):
        records = ""
        for record in self.records:
            records += record.record_to_string()
        return records



class EgtsRecord:
    """Contains information about EGTS record"""

    def __init__(self, **kwargs):
        self.rid = kwargs['rid']
        self.sst = kwargs['sst']
        if 'id' in kwargs:
            self.id = kwargs['id']
        self.rec_len = kwargs['rec_len']
        self.subrecords = kwargs['subrecords']

    @classmethod
    def parse(cls, buffer):
        if len(buffer) < EGTS_SERVICE_LAYER_MIN_RECORD_HEADER_LEN:
            raise EgtsPcIncHeaderForm("Record is shorter then EGTS_SERVICE_LAYER_MIN_RECORD_HEADER_LEN")
        data_len = int.from_bytes(buffer[:2], byteorder='little')
        rid = int.from_bytes(buffer[2:4], byteorder='little')
        tmfe = buffer[4] >> 2 & 1
        evfe = buffer[4] >> 1 & 1
        obfe = buffer[4] & 1
        opt_len = (tmfe + evfe + obfe) * 4
        header_len = EGTS_SERVICE_LAYER_MIN_RECORD_HEADER_LEN + opt_len
        if len(buffer) < header_len:
            raise EgtsPcIncHeaderForm("Record is shorter then EGTS_SERVICE_LAYER_MIN_RECORD_HEADER_LEN + opt_len")
        sst = buffer[5 + opt_len]
        kwargs = {'rid': rid, 'sst': sst, 'subrecords': []}
        if obfe:
            id = int.from_bytes(buffer[5:9], byteorder='little')
            kwargs['id'] = id
        rec_len = header_len + data_len
        kwargs['rec_len'] = rec_len
        rec = cls(**kwargs)
        if data_len > 0:
            if len(buffer) < rec_len:
                raise EgtsPcInvdatalen("Record")
            data = buffer[header_len:header_len+data_len]
            rec._analyze_subrecords(data)
        return rec

    def _analyze_subrecords(self, buff):
        while len(buff) > 0:
            sub, buff = self._analyze_subrecord(buff)
            self.subrecords.append(sub)

    def _analyze_subrecord(self, buffer):
        if len(buffer) < 3:
            raise EgtsPcInvdatalen("Subrecord header")
        srt = buffer[0]
        srl = int.from_bytes(buffer[1:3], byteorder='little')
        sub_len = 3 + srl
        if len(buffer) < sub_len:
            raise EgtsPcInvdatalen("Subrecord data")
        sub_data = buffer[3:sub_len]
        if srt == EGTS_PT_RESPONSE:
            sub = self._analyze_subrecord_response(sub_data)
        elif self.sst == EGTS_AUTH_SERVICE:
            sub = self._analyze_subrecord_auth(sub_data, srt)
        elif self.sst == EGTS_TELEDATA_SERVICE:
            sub = self._analyze_subrecord_tele(sub_data, srt)
        else:
            message = "sst = {0}; srt = {1}".format(self.sst, srt)
            raise EgtsPcSrvcUnkn(message)
        return sub, buffer[sub_len:]

    @staticmethod
    def _analyze_subrecord_response(buff):
        return EgtsResponse(buff)

    def _analyze_subrecord_auth(self, buff, srt):
        if srt == EGTS_SR_DISPATCHER_IDENTITY:
            return EgtsSrDispatcherIdentity.parse(buff, srt)
        else:
            return UnknownSubRecord(srt)

    def _analyze_subrecord_tele(self, buff, srt):
        if srt == EGTS_SR_POS_DATA:
            return EgtsSrPosData.parse(buff)
        else:
            return UnknownSubRecord(srt)

    def record_to_string(self):
        s = "{" + "RecNum: {0}, sst: {1}, ".format(self.rid, self.sst)
        if hasattr(self, "id"):
            s = s + "ID: " + str(self.id) + ", "
        subrecords = self.subrecords_to_string()
        s += "subrecords: [{0}]".format(subrecords) + "}"
        return s

    def subrecords_to_string(self):
        s = ""
        i = 1
        for subrecord in self.subrecords:
            s += subrecord.subrecord_to_string()
            if i != len(self.subrecords):
                s += ","
            i = i + 1
        return s

    def form_bin(self):
        b = b''
        for subrecord in self.subrecords:
            b += subrecord.form_bin()
        len_bin = len(b).to_bytes(2, 'little')
        rid_bin = self.rid.to_bytes(2, 'little')
        flags = 0
        id_bin = b''
        if self.id:
            flags = 1
            id_bin = self.id.to_bytes(4, 'little')
        sst_bin = self.sst.to_bytes(2, 'little')
        record = len_bin + rid_bin + bytes(flags) + id_bin + sst_bin + sst_bin + b
        return record


class EgtsSubRecord:
    """Contains information about EGTS subrecord"""

    def __init__(self, srt):
        self.type = srt

    def subrecord_to_string(self):
        return "Type: " + str(self.type)


class EgtsSrPosData(EgtsSubRecord):
    """Contains information about EGTS_SR_POS_DATA"""

    def __init__(self, **kwargs):
        super().__init__(EGTS_SR_POS_DATA)
        self.vld = kwargs.get('vld')
        self.ntm = kwargs.get('ntm')
        self.lat = kwargs.get('lat')
        self.long = kwargs.get('long')
        self.speed = kwargs.get('speed')
        self.dir = kwargs.get('dir')
        self.busy = kwargs.get('busy')
        self.src = kwargs.get('src')
        self.mv = kwargs.get('mv')
        self.bb = kwargs.get('bb')

    @classmethod
    def parse(cls, buffer):
        lohs = buffer[12] >> 6 & 1
        lahs = buffer[12] >> 5 & 1
        mv = buffer[12] >> 4 & 1
        bb = buffer[12] >> 3 & 1
        if buffer[12] & 1:
            vld = True
        else:
            vld = False
        ntm = (int.from_bytes(buffer[0:4], byteorder='little') + timestamp_20100101_000000_utc) * 1000
        lat = (int.from_bytes(buffer[4:8], byteorder='little') * 90 / 0xffffffff) * (1 - 2 * lahs)
        long = (int.from_bytes(buffer[8:12], byteorder='little') * 180 / 0xffffffff) * (1 - 2 * lohs)
        spd_hi = buffer[14] & 0b00111111
        spd_lo = buffer[13]
        speed = (spd_hi*256 + spd_lo) // 10
        dir_hi = buffer[14] >> 7
        dir_lo = buffer[15]
        dir = dir_hi*256 + dir_lo
        din = buffer[19]
        busy = din >> 7
        src = buffer[20]
        kwargs = {'vld': vld, 'ntm': ntm, 'lat': lat, 'long': long, 'speed': speed, 'dir': dir, 'busy': busy,
                  'src': src, 'mv': mv, 'bb': bb}
        return cls(**kwargs)

    def form_bin(self):
        time = self.ntm.to_bytes(4, 'little')
        lat = (abs(self.lat) / 90 * 0xffffffff).to_bytes(4, 'little')
        long = (abs(self.long) / 180 * 0xffffffff).to_bytes(4, 'little')
        lohs = 0
        lahs = 0
        if self.long < 0:
            lohs = 1
        if self.lat < 0:
            lahs = 1
        flags = lohs * 64 | lahs * 32 | self.mv * 16 | self.bb * 8 | 0x02 | self.vld
        spd_hi = self.speed * 10 / 256
        spd_lo = self.speed * 10 % 256
        bear_hi = self.dir / 256
        bear_lo = self.dir % 256
        flags2 = ((bear_hi << 0x07) | (spd_hi & 0x3F)) & 0xBF
        subrec = b'\x10\x00\x15' + time + lat + long + bytes(flags) + bytes(spd_lo) + bytes(flags2) + bytes(bear_lo) \
                 + b'\x00\x00\x00\x00' + bytes(self.src)
        return subrec

    def subrecord_to_string(self):
        s = "{" + super().subrecord_to_string() + ", "
        s += "vld: {0}, ntm: {1}, lat: {2}, long: {3}, speed: {4}," \
            " dir: {5}, busy: {6}, src: {7}".format(self.vld, self.ntm, self.lat,
                                                    self.long, self.speed, self.dir,
                                                    self.busy, self.src) + "}"
        return s

class UnknownSubRecord(EgtsSubRecord):
    """Contains information about subrecord unknown by egts-debugger"""
    def __init__(self, srt):
        super().__init__(srt)

    def subrecord_to_string(self):
        s = "{" + super().subrecord_to_string() + "}"
        return s


class EgtsResponse(EgtsSubRecord):
    """Contains information about response """

    def __init__(self, buffer):
        super().__init__(0)
        self.crn = buffer[0]
        self.rst = int.from_bytes(buffer[1:3], byteorder='little')

    def subrecord_to_string(self):
        s = "{" + super().subrecord_to_string() + ", "
        s += "Confirmed Record Number: {0}, Record Status: {1}".format(self.crn, self.rst) + "}"
        return s


class EgtsSrDispatcherIdentity(EgtsSubRecord):
    """Contains information about EGTS_SR_DISPATCHER_IDENTITY """

    def __init__(self, srt, **kwargs):
        super().__init__(srt)
        self.dt = kwargs.get('dt')
        self.did = kwargs.get('did')

    @classmethod
    def parse(cls, buffer, srt):
        dt = buffer[0]
        did = int.from_bytes(buffer[1:5], byteorder='little')
        kwargs = {'dt': dt, 'did': did}
        return cls(srt, **kwargs)

    def subrecord_to_string(self):
        s = "{" + super().subrecord_to_string() + ", "
        s += "dt: {0}, did: {1}".format(self.dt, self.did) + "}"
        return s
