"""
MPEG-2 Transport Stream parser.

Documentation:
- MPEG-2 Transmission
  http://erg.abdn.ac.uk/research/future-net/digital-video/mpeg2-trans.html

Author: Victor Stinner
Creation date: 13 january 2007
"""

from hachoir.parser import Parser
from hachoir.field import (FieldSet, ParserError, MissingField,
                           UInt8, UInt16, Enum, Bit, Bits, RawBytes, RawBits, String)
from hachoir.core.endian import BIG_ENDIAN
from hachoir.core.text_handler import textHandler, hexadecimal
from hachoir.parser.video import MovFile

class AdaptationField(FieldSet):

    def createFields(self):
        yield UInt8(self, "length")

        yield Bit(self, "discontinuity_indicator")
        yield Bit(self, "random_access_indicator")
        yield Bit(self, "es_prio_indicator")
        yield Bit(self, "has_pcr")
        yield Bit(self, "has_opcr")
        yield Bit(self, "has_splice_point")
        yield Bit(self, "private_data")
        yield Bit(self, "has_extension")

        if self['has_pcr'].value:
            yield Bits(self, "pcr_base", 33)
            yield Bits(self, "pcr_ext", 9)

        if self['has_opcr'].value:
            yield Bits(self, "opcr_base", 33)
            yield Bits(self, "opcr_ext", 9)

        if self['has_splice_point'].value:
            yield Bits(self, "splice_countdown", 8)

        stuff_len = ((self['length'].value + 1) * 8) - self.current_size
        if self['length'].value and stuff_len:
            yield RawBits(self, 'stuffing', stuff_len)

class Packet(FieldSet):

    def __init__(self, *args, **kw):
        self._m2ts = kw.pop('m2ts', False)
        FieldSet.__init__(self, *args, **kw)
        if self._m2ts:
            size = 4
        else:
            size = 0
        size += 188
        if self["has_error"].value:
            size += 16
        self._size = size * 8

    PID = {
        0x0000: "Program Association Table (PAT)",
        0x0001: "Conditional Access Table (CAT)",
        0x0002: "Transport Stream Description Table (TSDT)",
        0x0003: "IPMP Control Information Table",
        # 0x0004..0x000F: reserved
        0x0010: "NIT, ST",
        0x0011: "SDT, BAT, ST",
        0x0012: "EIT, ST, CIT",
        0x0013: "RST, ST",
        0x0014: "TDT, TOT, ST",
        0x0015: "network synchronization",
        0x0016: "RNT",
        #0x0017-0x001B: reserved for future use
        0x001C: "inband signalling",
        0x001D: "measurement",
        0x001E: "DIT",
        0x001F: "SIT",
        # 0x0010..0x1FFE: network PID, program map PID, elementary PID, etc.
        # 0x0020-0x1FFA	May be assigned as needed to Program Map Tables, elementary streams and other data tables
        0x1FFB: "DigiCipher 2/ATSC MGT metadata",
        # 0x1FFC-0x1FFE	May be assigned as needed to Program Map Tables, elementary streams and other data tables

        0x1FFF: "Null packet",
    }

    def createFields(self):
        if self._m2ts:
            yield Bits(self, "c", 2)
            yield Bits(self, "ats", 32 - 2)
        yield textHandler(UInt8(self, "sync", 8), hexadecimal)
        if self["sync"].value != 0x47:
            raise ParserError("MPEG-2 TS: Invalid synchronization byte")
        yield Bit(self, "has_error")
        yield Bit(self, "payload_unit_start")
        yield Bit(self, "priority")
        yield Enum(textHandler(Bits(self, "pid", 13, "Program identifier"), hexadecimal), self.PID)
        yield Bits(self, "scrambling_control", 2)
        yield Bit(self, "has_adaptation")
        yield Bit(self, "has_payload")
        yield Bits(self, "counter", 4)

        if self["has_adaptation"].value:
            yield AdaptationField(self, "adaptation_field")
        if self["has_payload"].value:
            size = 188
            if self._m2ts:
                size += 4
            size -= (self.current_size // 8)
            #yield RawBytes(self, "payload", size)
        
            if self["pid"]:
                yield RawBits(self, "table_id[]", 8)
                yield RawBits(self, "section_syntax_indicator[]", 1)
                yield RawBits(self, "ZERO[]", 1)
                yield RawBits(self, "reserved[]", 2)
                yield RawBits(self, "section_lenght[]", 12)
                yield RawBits(self, "transport_stream_id[]", 16)
                yield RawBits(self, "reserved[]", 2)
                yield RawBits(self, "version_number[]", 5)
                yield RawBits(self, "current_next_indicator[]", 1)
                yield RawBits(self, "section_number[]", 8)
                yield RawBits(self, "last_section_number[]", 8)

                while not self.eof:
                    yield textHandler(UInt16(self, "program_number[]", 16), hexadecimal)
                    yield RawBits(self, "reserved[]", 3)
                    yield RawBits(self, "network pid or program map pid[]", 13)

            #yield Payload(self, name='PAYLOAD', size=size)
        if self["has_error"].value:
            yield RawBytes(self, "error_correction", 16)

    def createDescription(self):
        text = "Packet: PID %s" % self["pid"].display
        if self["payload_unit_start"].value:
            text += ", start of payload"
        if self["has_adaptation"].value:
            text += ", with adaptation field"
        return text

    def isValid(self):
        if not self["has_payload"].value and not self["has_adaptation"].value:
            return "No payload and no adaptation"
        pid = self["pid"].value
        if (0x0002 <= pid <= 0x000f) or (0x2000 <= pid):
            return "Invalid program identifier (%s)" % self["pid"].display
        return ""


class Payload(FieldSet):
    def __init__(self, *args, **kw):
        self.my = kw.pop('size', 0)
        FieldSet.__init__(self, *args, **kw)

    def createFields(self):
        yield RawBytes(self, "CONTENT", self.my)

# M2TS 4 bytes + 188 bytes payload + 4 errors
MAX_PACKET_SIZE = 208


class MPEG_TS(Parser):
    PARSER_TAGS = {
        "id": "mpeg_ts",
        "category": "video",
        "file_ext": ("ts", "m2ts", "mts"),
        "min_size": 188 * 8,
        "mime": ("video/MP2T",),
        "description": "MPEG-2 Transport Stream"
    }
    endian = BIG_ENDIAN

    def is_m2ts(self):
        # FIXME: detect using file content, not file name
        # maybe detect sync at offset+4 bytes?
        source = self.stream.source
        if not(source and source.startswith("file:")):
            return True
        filename = source[5:].lower()
        return filename.endswith((".m2ts", ".mts"))

    def validate(self):
        sync = self.stream.searchBytes(b"\x47", 0, MAX_PACKET_SIZE * 8)
        if sync is None:
            return "Unable to find synchronization byte"
        for index in range(5):
            try:
                packet = self["packet[%u]" % index]
            except (ParserError, MissingField):
                if index and self.eof:
                    return True
                else:
                    return "Unable to get packet #%u" % index
            err = packet.isValid()
            if err:
                return "Packet #%u is invalid: %s" % (index, err)
        return True

    def createFields(self):
        m2ts = self.is_m2ts()

        while not self.eof:
            current = self.current_size
            next_sync = current
            if m2ts:
                next_sync += 4 * 8
            sync = self.stream.searchBytes(b"\x47", current,
                                           current + MAX_PACKET_SIZE * 8)
            if sync is None:
                raise ParserError("Unable to find synchronization byte")
            elif sync > next_sync:
                yield RawBytes(self, "incomplete_packet[]",
                               (sync - current) // 8)
            yield Packet(self, "packet[]", m2ts=m2ts)
