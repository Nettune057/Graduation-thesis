import re

class FlowEntry:
    def __init__(self, input_str: str):
        self._input = input_str
        self._match = None
        self.Cookie = None
        self.Duration = None
        self.Table = None
        self.NPackets = None
        self.NBytes = None
        self.IdleTimeout = None
        self.HardTimeout = None
        self.Priority = None
        self.InPort = None
        self.VLANTCI = None
        self.Arp = False
        self.DLSrc = None
        self.DLDst = None
        self.ARPSrcIP = None
        self.ARPTgtIP = None
        self.ARPOperation = None
        self.Icmp = False
        self.NWSrc = None
        self.NWDst = None
        self.NWTos = None
        self.IcmpType = None
        self.IcmpCode = None
        self.Actions = None
        self.parse()

    def parse(self):
        self.Cookie = self._try_parse(r'^ cookie=0x[\w-]{1,8}')
        self.Duration = self._try_parse(r'duration=\d{1,8}\.[\d-]{1,8}')
        self.Table = self._try_parse(r'table=[\d-]{1,8}')
        self.NPackets = self._try_parse(r'n_packets=[\d-]{1,9}')
        self.NBytes = self._try_parse(r'n_bytes=[\d-]{1,8}')
        self.IdleTimeout = self._try_parse(r'idle_timeout=[\d-]{1,8}')
        self.HardTimeout = self._try_parse(r'hard_timeout=[\d-]{1,8}')
        self.Priority = self._try_parse(r'priority=[\d-]{1,8}')
        self.InPort = self._try_parse(r'in_port=["123456789]{1,9}')
        self.VLANTCI = self._try_parse(r'vlan_tci=0x[\d]{4}')
        self.Arp = bool(re.search(r'arp', self._input))
        self.DLSrc = self._try_parse(r'dl_src=..:..:..:..:..:..')
        self.DLDst = self._try_parse(r'dl_dst=..:..:..:..:..:..')
        self.ARPSrcIP = self._try_parse(r'arp_spa=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        self.ARPTgtIP = self._try_parse(r'arp_tpa=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        self.ARPOperation = self._try_parse(r'arp_op=\d{1}')
        self.Actions = self._try_parse(r'actions=[\S]{1,30}$')
        self.Icmp = bool(re.search(r'icmp', self._input))
        self.NWSrc = self._try_parse(r'nw_src=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        self.NWDst = self._try_parse(r'nw_dst=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        self.NWTos = self._try_parse(r'nw_tos=\d{1,3}')
        self.IcmpType = self._try_parse(r'icmp_type=\d{1,3}')
        self.IcmpCode = self._try_parse(r'icmp_code=\d{1,3}')
    
    def __str__(self) -> str:
        return f"{self.DLSrc} {self.DLDst}"
    
    def _try_parse(self, regex: str) -> str:
        match = re.search(regex, self._input)
        if match:
            return match.group(0)[match.group().index('=') + 1:]
        return None
    
    # Parse a list of entries from a string


# import Foo

# Foo.parse('d')