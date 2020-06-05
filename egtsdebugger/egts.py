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
EGTS_COMMANDS_SERVICE = 4
EGTS_SR_DISPATCHER_IDENTITY = 5
EGTS_SR_AUTH_PARAMS = 6
EGTS_SR_AUTH_INFO = 7
EGTS_SR_RESULT_CODE = 9
EGTS_SR_POS_DATA = 16
EGTS_SR_AD_SENSORS_DATA = 18
EGTS_SR_ABS_AN_SENS_DATA = 24
EGTS_SR_LIQUID_LEVEL_SENSOR = 27
EGTS_SR_COMMAND_DATA = 51
# EGTS_SR_COMMAND_DATA command types
CT_COMCONF = 0b0001
CT_MSGCONF = 0b0010
CT_MSGFROM = 0b0011
CT_MSGTO = 0b0100
CT_COM = 0b0101
CT_DELCOM = 0b0110
CT_SUBREQ = 0b0111
CT_DELIV = 0b1000

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

EGTS_MAX_PACKET_LENGTH = 65535

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
    def form_bin(pid, records):
        body = Egts._body_bin(records)
        packet = Egts._packet_bin(pid, body, EGTS_PT_APPDATA)
        return packet

    def reply(self, ans_pid, ans_rid):
        subrecords = self._reply_record()
        pack_id = self.pid.to_bytes(2, 'little')
        body = pack_id + b'\x00' + Egts._make_record(self.service, ans_rid, subrecords)
        reply = self._packet_bin(ans_pid, body, EGTS_PT_RESPONSE)
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
    def _packet_bin(ans_pid, body, type):
        bcs = crc16_func(body)
        data_len = len(body)
        header = Egts._make_header(ans_pid, data_len, type)
        hcs = crc8_func(header)
        bcs_bin = bcs.to_bytes(2, 'little')
        reply = header + hcs.to_bytes(1, 'little') + body + bcs_bin
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
            record = rec.form_bin()
            res += record
        return res

    @staticmethod
    def _make_header(ans_pid, data_len, type):
        rec_len = data_len.to_bytes(2, 'little')
        ans_rid_bin = ans_pid.to_bytes(2, 'little')
        header = b'\x01\x00\x03\x0b\x00' + rec_len + ans_rid_bin + type.to_bytes(1, 'little')
        return header

    @staticmethod
    def _make_record(service, ans_rid, subrecords):
        sub_len = len(subrecords).to_bytes(2, 'little')
        rid = ans_rid.to_bytes(2, 'little')
        body = sub_len + rid + b'\x18' + service.to_bytes(1, 'little') + service.to_bytes(1, 'little') + subrecords
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
        if 'rec_len' in kwargs:
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
        elif self.sst == EGTS_COMMANDS_SERVICE:
            sub = self._analyze_subrecord_comm(sub_data, srt)
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
        if srt == EGTS_SR_AUTH_PARAMS:
            return EgtsSrAuthParams.parse(buff, srt)
        if srt == EGTS_SR_RESULT_CODE:
            return EgtsSrResultCode.parse(buff, srt)
        else:
            return UnknownSubRecord(srt)

    def _analyze_subrecord_tele(self, buff, srt):
        if srt == EGTS_SR_POS_DATA:
            return EgtsSrPosData.parse(buff)
        elif srt == EGTS_SR_AD_SENSORS_DATA:
            return EgtsSrAdSensorsData.parse(buff)
        elif srt == EGTS_SR_ABS_AN_SENS_DATA:
            return EgtsSrAbsAnSensData.parse(buff)
        elif srt == EGTS_SR_LIQUID_LEVEL_SENSOR:
            return EgtsSrLiquidLevelSensor.parse(buff)
        else:
            return UnknownSubRecord(srt)

    def _analyze_subrecord_comm(self, buff, srt):
        if srt == EGTS_SR_COMMAND_DATA:
            return EgtsSrCommandData.parse(buff, srt)
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
        try:
            id_bin = self.id.to_bytes(4, 'little')
            flags |= 0b00000001
        except AttributeError:
            pass
        sst_bin = self.sst.to_bytes(1, 'little')
        record = len_bin + rid_bin + flags.to_bytes(1, 'little') + id_bin + sst_bin + sst_bin + b
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
        self.long = kwargs.get('lon')
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
        kwargs = {'vld': vld, 'ntm': ntm, 'lat': lat, 'lon': long, 'speed': speed, 'dir': dir, 'busy': busy,
                  'src': src, 'mv': mv, 'bb': bb}
        return cls(**kwargs)

    def form_bin(self):
        time = int(self.ntm/1000 - timestamp_20100101_000000_utc).to_bytes(4, 'little')
        lat = round((abs(self.lat) / 90 * 0xffffffff)).to_bytes(4, 'little')
        long = round((abs(self.long) / 180 * 0xffffffff)).to_bytes(4, 'little')
        lohs = 0
        lahs = 0
        if self.long < 0:
            lohs = 1
        if self.lat < 0:
            lahs = 1
        flags = lohs * 64 | lahs * 32 | self.mv * 16 | self.bb * 8 | 0x02 | self.vld
        spd_hi = round(self.speed * 10 / 256)
        spd_lo = round(self.speed * 10 % 256)
        bear_hi = round(self.dir // 256)
        bear_lo = round(self.dir % 256)
        flags2 = ((bear_hi << 0x07) | (spd_hi & 0x3F)) & 0xBF
        subrec = b'\x10\x15\x00' + time + lat + long + flags.to_bytes(1, 'little') + spd_lo.to_bytes(1, 'little') + \
                 flags2.to_bytes(1, 'little') + bear_lo.to_bytes(1, 'little') + b'\x00\x00\x00\x00' + \
                 self.src.to_bytes(1, 'little')
        return subrec

    def subrecord_to_string(self):
        s = "{" + super().subrecord_to_string() + ", "
        s += "vld: {0}, ntm: {1}, lat: {2}, long: {3}, speed: {4}," \
            " dir: {5}, busy: {6}, src: {7}".format(self.vld, self.ntm, self.lat,
                                                    self.long, self.speed, self.dir,
                                                    self.busy, self.src) + "}"
        return s

class EgtsSrAdSensorsData(EgtsSubRecord):
    """Contains information about EGTS_SR_AD_SENSORS_DATA"""

    def __init__(self, **kwargs):
        super().__init__(EGTS_SR_AD_SENSORS_DATA)
        self.dioe = kwargs.get('dioe')
        self.dout = kwargs.get('dout')
        self.asfe = kwargs.get('asfe')
        self.adio = kwargs.get('adio')
        self.ans = kwargs.get('ans')

    @classmethod
    def parse(cls, buffer):
        dioe = buffer[0]
        dout = buffer[1]
        asfe = buffer[2]
        offset = 3
        adio = {}
        for i in range(8):
            if dioe & (0b1 << i):
                adio[i+1] = buffer[offset]
                offset += 1
        ans = {}
        for i in range(8):
            if asfe & (0b1 << i):
                ans[i+1] = int.from_bytes(buffer[offset:offset+3], byteorder='little')
                offset += 3
        kwargs = {'dioe': dioe, 'dout': dout, 'asfe': asfe, 'adio': adio, 'ans': ans}
        return cls(**kwargs)

    def subrecord_to_string(self):
        s = "{" + super().subrecord_to_string() + ", "
        s += "dioe: {0:#010b}, dout: {1:#010b}, asfe: {2:#010b}".format(self.dioe, self.dout, self.asfe)
        for k in sorted(self.adio):
            s += ", adio{0}: {1:#010b}".format(k, self.adio[k])
        for k in sorted(self.ans):
            s += ", ans{0}: {1}".format(k, self.ans[k])
        s += "}"
        return s

class EgtsSrAbsAnSensData(EgtsSubRecord):
    """Contains information about EGTS_SR_ABS_AN_SENS_DATA"""

    def __init__(self, **kwargs):
        super().__init__(EGTS_SR_ABS_AN_SENS_DATA)
        self.asn = kwargs.get('asn')
        self.asv = kwargs.get('asv')

    @classmethod
    def parse(cls, buffer):
        asn = buffer[0]
        asv = int.from_bytes(buffer[1:4], byteorder='little')
        kwargs = {'asn': asn, 'asv': asv}
        return cls(**kwargs)

    def subrecord_to_string(self):
        s = "{" + super().subrecord_to_string() + ", "
        s += "asn: {0}, asv: {1}".format(self.asn, self.asv) + "}"
        return s

class EgtsSrLiquidLevelSensor(EgtsSubRecord):
    """Contains information about EGTS_SR_LIQUID_LEVEL_SENSOR"""

    def __init__(self, **kwargs):
        super().__init__(EGTS_SR_LIQUID_LEVEL_SENSOR)
        self.llsef = kwargs.get('llsef')
        self.llsvu = kwargs.get('llsvu')
        self.rdf = kwargs.get('rdf')
        self.llsn = kwargs.get('llsn')
        self.maddr = kwargs.get('maddr')
        self.llsd = kwargs.get('llsd')

    @classmethod
    def parse(cls, buffer):
        llsef = (buffer[0] >> 6) & 0b1
        llsvu = (buffer[0] >> 4) & 0b11
        rdf = (buffer[0] >> 3) & 0b1
        llsn = buffer[0] & 0b111
        maddr = int.from_bytes(buffer[1:3], byteorder='little')
        if rdf == 0:
            llsd = int.from_bytes(buffer[3:7], byteorder='little')
        else:
            llsd = buffer[3:]
        kwargs = {'llsef': llsef, 'llsvu': llsvu, 'rdf': rdf, 'llsn': llsn, 'maddr': maddr, 'llsd': llsd}
        return cls(**kwargs)

    def subrecord_to_string(self):
        s = "{" + super().subrecord_to_string() + ", "
        s += "llsef: {0:#b}, llsvu: {1:#04b}, rdf: {2:#b}, llsn: {3}, maddr: {4}, " \
             "llsd: {5}".format(self.llsef, self.llsvu, self.rdf, self.llsn, self.maddr, self.llsd) + "}"
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
        self.crn = int.from_bytes(buffer[0:2], byteorder='little')
        self.rst = buffer[2]

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

    def form_bin(self):
        srt = self.type.to_bytes(1, 'little')
        srd = self.dt.to_bytes(1, 'little') + self.did.to_bytes(4, 'little')
        srl = len(srd).to_bytes(2, 'little')
        subrec = srt + srl + srd
        return subrec

class EgtsSrAuthParams(EgtsSubRecord):
    """Contains information about EGTS_SR_AUTH_PARAMS"""

    def __init__(self, srt, **kwargs):
        super().__init__(srt)
        self.flg = kwargs.get('flg')

    @classmethod
    def parse(cls, buffer, srt):
        flg = buffer[0]
        kwargs = {'flg': flg}
        return cls(srt, **kwargs)

    def subrecord_to_string(self):
        s = "{" + super().subrecord_to_string() + ", "
        s += "flg: {0}".format(self.flg)
        return s

class EgtsSrAuthInfo(EgtsSubRecord):
    """Contains information about EGTS_SR_AUTH_INFO"""

    def __init__(self, srt, **kwargs):
        super().__init__(srt)
        self.unm = kwargs.get('unm')
        self.upsw = kwargs.get('upsw')

    def form_bin(self):
        srt = self.type.to_bytes(1, 'little')
        unm = self.unm.encode()
        upsw = self.upsw.encode()
        srd = unm + b'\x00' + upsw + b'\x00'
        srl = len(srd).to_bytes(2, 'little')
        subrec = srt + srl + srd
        return subrec

class EgtsSrResultCode(EgtsSubRecord):
    """Contains information about EGTS_SR_RESULT_CODE"""
    def __init__(self, srt, **kwargs):
        super().__init__(srt)
        self.rcd = kwargs.get('rcd')

    @classmethod
    def parse(cls, buffer, srt):
        rcd = buffer[0]
        kwargs = {'rcd': rcd}
        return cls(srt, **kwargs)

    def subrecord_to_string(self):
        s = "{" + super().subrecord_to_string() + ", "
        s += "rcd: {0}".format(self.rcd)
        return s


class EgtsSrCommandData(EgtsSubRecord):
    """Contains information about EGTS_SR_COMMAND_DATA"""
    def __init__(self, srt, **kwargs):
        super().__init__(srt)
        self.ct = kwargs.get('ct')
        self.cct = kwargs.get('cct')
        self.cid = kwargs.get('cid')
        self.sid = kwargs.get('sid')
        self.acfe = kwargs.get('acfe')
        self.chsfe = kwargs.get('chsfe')
        self.chs = kwargs.get('chs')
        self.acl = kwargs.get('acl')
        self.ac = kwargs.get('ac')
        self.adr = kwargs.get('adr')
        self.sz = kwargs.get('sz')
        self.act = kwargs.get('act')
        self.ccd = kwargs.get('ccd')
        self.dt = kwargs.get('dt')

    @classmethod
    def parse(cls, buffer, srt):
        ct = buffer[0] >> 4
        cct = buffer[0] & 0b00001111
        cid = int.from_bytes(buffer[1:5], byteorder='little')
        sid = int.from_bytes(buffer[5:9], byteorder='little')
        acfe = (buffer[9] & 0b00000010) >> 1
        chsfe = (buffer[9] & 0b00000001)
        kwargs = {'ct': ct, 'cct': cct, 'cid': cid, 'sid': sid, 'acfe': acfe, 'chsfe': chsfe}
        offset = 10
        if chsfe:
            chs = buffer[offset]
            offset += 1
            kwargs['chs'] = chs
        if acfe:
            acl = buffer[offset]
            offset += 1
            kwargs['acl'] = acl
            ac = buffer[offset:offset+acl]
            offset += acl
            kwargs['ac'] = ac
        cd = buffer[offset:]
        if ct in (CT_COMCONF, CT_MSGCONF, CT_MSGFROM):
            adr = int.from_bytes(cd[0:2], byteorder='little')
            ccd = int.from_bytes(cd[2:4], byteorder='little')
            dt = cd[4:]
            kwargs.update({'adr': adr, 'ccd': ccd, 'dt': dt})
        elif ct in (CT_MSGTO, CT_COM, CT_DELCOM, CT_SUBREQ):
            adr = int.from_bytes(cd[0:2], byteorder='little')
            sz = cd[2] >> 4
            act = cd[2] & 0b00001111
            ccd = int.from_bytes(cd[3:5], byteorder='little')
            dt = cd[5:]
            kwargs.update({'adr': adr, 'sz': sz, 'act': act, 'ccd': ccd, 'dt': dt})
        return cls(srt, **kwargs)

    def subrecord_to_string(self):
        s = "{" + super().subrecord_to_string() + ", "
        s += "ct: {0}, ".format(self.ct)
        s += "cct: {0}, ".format(self.cct)
        s += "cid: {0}, ".format(self.cid)
        s += "sid: {0}, ".format(self.sid)
        s += "acfe: {0}, ".format(self.acfe)
        s += "chsfe: {0}, ".format(self.chsfe)
        if self.chsfe:
             s += 'hs: {0}, '.format(self.chs)
        if self.acfe:
            s += 'acl: {0}, '.format(self.acl)
            s += 'ac: {0}, '.format(self.ac)
        if self.ct in (CT_COMCONF, CT_MSGCONF, CT_MSGFROM):
            s += 'adr: {0}, '.format(self.adr)
            s += 'ccd: {0}, '.format(self.ccd)
            s += 'dt: "{0}"'.format(self.dt.rstrip(b'\x00').decode('utf8'))
        elif self.ct in (CT_MSGTO, CT_COM, CT_DELCOM, CT_SUBREQ):
            s += 'adr: {0}, '.format(self.adr)
            s += 'sz: {0}, '.format(self.sz)
            s += 'act: {0}, '.format(self.act)
            s += 'ccd: {0}, '.format(self.ccd)
            s += 'dt: "{0}"'.format(self.dt.rstrip(b'\x00').decode('utf8'))
        s += "}"
        return s
