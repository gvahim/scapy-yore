# YORE
conf.netcache.new_cache("yoarp_cache", 120) # cache entries expire after 120s

# YORE
@conf.commands.register
def register_yoip(yoip):
    conf.yoip = yoip
 
register_yoip("0.0")

# YORE
@conf.commands.register
def getmacbyyoip(yoip, chainCC=0):
 
    """Return MAC address corresponding to a given YOIP address"""

    # YORE TODO: is 0.0.0.0 a good enough default? I think so.
    iff,a,gw = conf.route.route("0.0.0.0")

    src_mac = get_if_hwaddr(iff)

    try:
        myyoip = conf.yoip
    except:
        myyoip = None

    if (myyoip == yoip):
        return src_mac


    if (yoip == "0.0"):
        return "00:00:00:00:00:00"

    if (yoip == "255.255"):
        return "ff:ff:ff:ff:ff:ff"

    mac = conf.netcache.yoarp_cache.get(yoip)
    if mac:
        return mac

    print "GETTING MAC BY IP"

    pkt = Ether(src=src_mac, dst=ETHER_BROADCAST)/YOARP(op="who-has", hwsrc=src_mac, psrc=conf.yoip, pdst=yoip)
    # TODO: Do we need to fix anything in "answers"?

    res = srp1(pkt,
                iface = iff,
                timeout=5,
                verbose=0,
                retry=3,
                chainCC=chainCC,
                nofilter=1 ) 
                
    if res is not None:
        mac = res.payload.hwsrc
        conf.netcache.yoarp_cache[yoip] = mac
        return mac



class Ether(Packet):
    name = "Ethernet"
    fields_desc = [ DestMACField("dst"),
                    SourceMACField("src"),
                    XShortEnumField("type", 0x9000, ETHER_TYPES) ]
    def hashret(self):
        return struct.pack("H",self.type)+self.payload.hashret()
    def answers(self, other):
        if isinstance(other,Ether):
            if self.type == other.type:
                return self.payload.answers(other.payload)
        return 0
    def mysummary(self):
        return self.sprintf("%src% > %dst% (%type%)")
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 14:
            if struct.unpack("!H", _pkt[12:14])[0] <= 1500:
                return Dot3
        return cls

    # YORE 
    def guess_payload_class(self, payload):
        if self.type == 2054 and len(payload) > 4:
            if payload[2:4] == "\x99\x99":
                return YOARP
            elif payload[2:4] == "\x08\x00":
                return ARP
        return Packet.guess_payload_class(self, payload)


# YORE
class YOARP(Packet):
    name = "YOARP"
    fields_desc = [ XShortField("hwtype", 0x0001),
                    XShortEnumField("ptype",  0x9999, ETHER_TYPES),
                    ByteField("hwlen", 6),
                    ByteField("plen", 2),
                    ShortEnumField("op", 1, {"who-has":1, "is-at":2, "RARP-req":3, "RARP-rep":4, "Dyn-RARP-req":5, "Dyn-RAR-rep":6, "Dyn-RARP-err":7, "InARP-req":8, "InARP-rep":9}),
                    ARPSourceMACField("hwsrc"),
                    YOIPField("psrc", "0.0"),
                    MACField("hwdst", ETHER_ANY),
                    YOIPField("pdst", "0.0") ]
    who_has = 1
    is_at = 2

    def extract_padding(self, s):
        return "",s

    def answers(self, other):
        if isinstance(other,YOARP):
            if ( (self.op == self.is_at) and
                 (other.op == self.who_has) and
                 (self.psrc == other.pdst) ):
                return 1
        return 0

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 4 and _pkt[2:4] == "\x08\x00":
            return ARP
        return cls

# YORE
conf.neighbor.register_l3(Ether, YOARP, lambda l2,l3: getmacbyyoip(l3.pdst))