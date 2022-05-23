import socket
import sys
import logging
logging.basicConfig(format="[%(levelname)s] %(asctime)s %(message)s", level=logging.DEBUG)

IP_RECVERR = 11
IP_RECVTTL = 12
MSG_ERRQUEUE    = 0x2000
TTL_EXPIRED = 11
DESTINATION_UNREACHABLE = 3
ERROR_REASON_ICMP = 2
ICMP_TYPE_OFFSET=5
DEFAULT_MAX_TTL= 1
DEFAULT_TRACEROUTE_TIMEOUT= 0.2

if not '__socket_plus__' in globals():
    globals()['__socket_plus__']={
        'settings':{
            'debug':False,
            'error_handling':False,
            'auto_traceroute': False,
            'static_source_port': False,
            'initial_ttl': 64
        },
        'list':[],
        'src_ip':{},
        'dst_ip':{}
        }

class DebugSocket(socket.socket):
    _settings=globals()['__socket_plus__']['settings']
    def __init__(self, family=-1, type=-1, proto=-1, fileno=None):
        super().__init__(family, type, proto, fileno)
        self._log=logging.getLogger(__file__)
        
        self.__ttl=self._settings['initial_ttl']
        self._dst_address=None
        self._dst_port=None
        self._src_address=None
        self._src_port=None
        self._last_sent_bytes=None
        self._last_sent_flags=None
        self._last_error=None
        self._socket_infos={
            'src_ip':None,
            'dst_ip':None,
            'src_port': None,
            'dst_port':None,
            'hops':[]
        }
        


    @property
    def set_source_port(self,port):
        self._src_port=port

    def bind_source_port(self):
        if self._src_port:
            if self._src_address:
                self.bind((self._src_address,int(self._src_port)))
                self._log.debug(f'Bound to static source port {self._src_address}:{self._src_port}')
            else:
                self.bind(('0.0.0.0',int(self._src_port)))
                self._log.debug(f'Bound to static source port 0.0.0.0:{self._src_port}')
        self._log.debug(f'No static source port defined using dynamic ephemeral port')
        
    def set_ttl(self,ttl):
        self._log.debug(f'Setting TTL to {ttl}')
        self.__ttl=ttl
        self.setsockopt(socket.SOL_IP, socket.IP_TTL, self.__ttl)
    
    def enable_error_handling(self):
        self.setsockopt(socket.IPPROTO_IP, IP_RECVERR, int(True))
        self.setsockopt (socket.SOL_IP, IP_RECVTTL, int(True))
        self._log.debug('Enabled IP_RECVERR and IP_RECVTTL flags on socket')

    # def check_errors(self,max_packet_size=65535):
    #     self._log.debug('checking for icmp errors')
    #     sleep(DEFAULT_TRACEROUTE_TIMEOUT)
    #     try:            
    #         recv, ancdata, flags, addr = self.recvmsg(max_packet_size,65535,MSG_ERRQUEUE)
    #         if ancdata[0][1] == ERROR_REASON_ICMP:
    #             reporting_ip='.'.join([str(i) for i in ancdata[1][2][20:24]])
    #             if ancdata[1][2][ICMP_TYPE_OFFSET] == TTL_EXPIRED:
    #                 self._log.error (f'got icmp error TTL_EXPIRED from {reporting_ip}')
    #                 if self.auto_traceroute:
    #                     self._log.debug('auto traceroute enabled')
    #                     self.__ttl+=1
    #                     self._log.debug(f'ttl is now {self.__ttl}')
    #                     return self.send(self._last_sent_bytes, self._last_sent_flags)
    #             elif ancdata[1][2][ICMP_TYPE_OFFSET] == DESTINATION_UNREACHABLE:
    #                 # pass
    #                 print (f'got icmp error DESTINATION_UNREACHABLE from {reporting_ip}')
    #     except BlockingIOError:
    #         # if retry:
    #         #     self._log.debug(f'no error response, waiting for {DEFAULT_TRACEROUTE_TIMEOUT} seconds until retry')
                
    #         #     self.check_errors(max_packet_size,False)
    #         pass

    def connect(self, __address):
        self._dst_address=__address[0]
        self._dst_port=__address[1]
        if self._settings['static_source_port']:
            self._src_port=int(self._settings['static_source_port'])
        self.bind_source_port()
        con=super().connect(__address)
        self._src_address, self._src_port=self.getsockname()
        self._log.debug(f'Opened connection from {self._src_address}:{self._src_port} to {self._dst_address}:{self._dst_port}')
        return con    

    def send(self,bytes,flags=0):
        self.set_ttl(self.__ttl)
        # if self._settings['static_source_port']:
        #     self.set_source_port(int(self._settings['static_source_port']))
        #     self.bind_source_port()
        self._log.debug(f'Sending {len(bytes)} bytes from {self._src_address}:{self._src_port} to {self._dst_address}:{self._dst_port}')
        if self._settings['debug'] == 'packet':
            hex_data=':'.join(format(c, '02x') for c in bytes)
            self._log.debug(f'Packet data: {hex_data}')
        self._last_sent_bytes=bytes
        self._last_sent_flags=flags
        if self._settings['error_handling']:
            self.enable_error_handling()
        result=super().send(bytes,flags)

        return result
    
    def handle_ancdata(self, ancdata):
        try: 
            if ancdata[0][1] == ERROR_REASON_ICMP:
                reporting_ip='.'.join([str(i) for i in ancdata[1][2][20:24]])
                if ancdata[1][2][ICMP_TYPE_OFFSET] == TTL_EXPIRED:
                    self._log.error (f'Got ICMP error TTL_EXPIRED from {reporting_ip}')
                    self._last_error='TTL_EXPIRED'
                elif ancdata[1][2][ICMP_TYPE_OFFSET] == DESTINATION_UNREACHABLE:
                    self._last_error='DESTINATION_UNREACHABLE'
                    self._log.error (f'got ICMP error DESTINATION_UNREACHABLE from {reporting_ip}')
        except Exception:
            self._log.error (f'Cannot parse ancdata {ancdata}')
        return 
    def recv(self,max_packet_size):
        # if self._settings['error_handling']:
        try:
            data, ancdata, msg_flags, address = super().recvmsg(max_packet_size, 65535)
        except OSError:
            data, ancdata, msg_flags, address = self.recvmsg(max_packet_size, 65535, MSG_ERRQUEUE)
        self.handle_ancdata(ancdata)
        # from pprint import pprint
        # pprint(data)
        # pprint(ancdata)
        return data



# register socketPlus
sys.modules['socket'].socket=DebugSocket
# print(dir(sys.modules['socket']))
