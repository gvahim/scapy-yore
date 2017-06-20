import struct
from scapy.config import conf
from scapy.fields import Field


class YOIPField(Field):
    def __init__(self, name, default):
        super(self.__class__, self).__init__(name, default, '2s')

    def h2i(self, pkt, x):
        if isinstance(x, basestring):
            a, b = x.split(".")
            return struct.unpack(">H", struct.pack(">BB", int(a), int(b)))[0]
        elif type(x) is list:
            x = [self.h2i(pkt, n) for n in x]
        return x

    def resolve(self, x):
        if self in conf.resolve:
            (a, b) = struct.unpack(">BB", x)
            return "%d.%d" % (a, b)

    def i2m(self, pkt, x):
        return struct.pack(">H", x)

    def m2i(self, pkt, x):
        return struct.unpack(">H", x)[0]

    def any2i(self, pkt, x):
        return self.h2i(pkt, x)

    def i2h(self, pkt, x):
        a, b = struct.pack(">H", x)
        return "%d.%d" % (ord(a), ord(b))

    def i2repr(self, pkt, x):
        return self.i2h(pkt, x)

    def m2h(self, pkt, x):
        a, b = x[0], x[1]
        return "%d.%d" % (ord(a), ord(b))

    def randval(self):
        return 4000
