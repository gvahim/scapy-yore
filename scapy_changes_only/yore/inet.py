import struct

from l2 import get_mac_by_yoip
from yore_fields import YOIPField
from scapy.config import conf
from scapy.layers.inet import Ether, Raw
from scapy.packet import Packet, bind_layers
from scapy.fields import (XShortField, XByteField, ShortField,
                          ByteEnumField, ByteField, FlagsField)


class YOREPacket(Packet):
    # As ripped off from https://gist.github.com/eaydin/768a200c5d68b9bc66e7
    # check Licensing.
    def calc_check_sum(self, data):
        msg_byte = self.hex_str_to_byte(data)
        check = 0
        for i in msg_byte:
            check = self.add_to_crc(i, check)
        return check

    @staticmethod
    def hex_str_to_byte(msg):
        hex_data = msg.decode("hex")
        msg = bytearray(hex_data)
        return msg

    @staticmethod
    def add_to_crc(b, crc):
        b2 = b
        if b < 0:
            b2 = b + 256
        for i in xrange(8):
            odd = ((b2 ^ crc) & 1) == 1
            crc >>= 1
            b2 >>= 1
            if odd:
                crc ^= 0x8C  # this means crc ^= 140
        return crc


class YO(YOREPacket):
    name = "YO"
    fields_desc = [
        XShortField("magic", 0x594F),
        XByteField("version", 1),
        ShortField("len", None),
        ByteField("hop", 0x10),
        ByteEnumField("opcode", 1, {0: "ping", 1: "pong", 2: "RE", 255: "raw"}),
        XByteField("chksum", None),
        XByteField("reserved", 0),
        YOIPField("dst", "0.0"),
        YOIPField("src", "1.1")
    ]

    def post_build(self, p, pay):
        if self.len is None:
            l = len(p) + len(pay)
            p = p[:3] + struct.pack("!H", l) + p[5:]
        if self.chksum is None:
            ck = self.calc_check_sum(p.encode("hex"))
            p = p[:7] + chr(ck) + p[8:]
        return p + pay

    def verify_checksum(self):
        print "IMPLEMENT ME"
        return

    # YORE TODO
    # Fix this to something that makes more sense?
    # Maybe this is good enough. wifi is not working.
    def route(self):
        if self.dst == "0.0":
            print "YORE DEBUG: default config"
            return conf.iface, "0.0", "0.0."
        else:
            # print ("YORE DEBUG: route function took conf "
            #        "%s %s %s") % (conf.iface, self.dst, conf.yoip)
            return conf.iface, self.dst, conf.yoip
            # return ("lo0", self.dst,"0.0")

    def answers(self, other):
        if not isinstance(other, YO):
            return 0

        if self.opcode == 0:
            return 0

        if (self.dst, self.src) == (other.src, other.dst):
            if self.opcode == 1:
                return 1
            else:
                return self.payload.payload.answers(other)


class RE(YOREPacket):
    name = "RE"
    fields_desc = [
        XShortField("magic", 0x5245),
        XByteField("version", 1),
        ShortField("len", None),
        ShortField("sid", 0),
        FlagsField("flags", 0x0, 8, "SAFE"),
        ByteField("seq", 0x0),
        ByteField("ack", 0x0),
        XByteField("chksum", None)
    ]

    def post_build(self, p, pay):
        if self.len is None:
            l = len(p) + len(pay)
            p = p[:3] + struct.pack("!H", l) + p[5:]
        if self.chksum is None:
            ck = self.calc_check_sum(p.encode("hex"))
            p = p[:10] + chr(ck)
        return p + pay

    def answers(self, other):
        if not isinstance(other, RE):
            return 0
        if self.sid != other.sid:
            return 0
        # TODO YORE IMPLEMENT MORE
        return 1


# # TODO FIX
#    def extract_padding(self, s):        
#        return s[11:]


bind_layers(Ether, YO, type=0x9998)
bind_layers(YO, RE, opcode=2)
bind_layers(YO, Raw, opcode=0xFF)

conf.neighbor.register_l3(Ether, YO, lambda l2, l3: get_mac_by_yoip(l3.dst))
