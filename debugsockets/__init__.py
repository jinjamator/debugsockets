import socket
import sys
import logging
import time
from copy import deepcopy
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

from collections import defaultdict

def tree():
    return defaultdict(tree)

class DestinationUnreachable(Exception):
    pass

class DebugSocket(socket.socket):
    global_settings=tree()
    default_settings={
            'enabled':False,
            'debug':False,
            'error_handling':False,
            'auto_traceroute': False,
            'static_source_port': False,
            'initial_ttl': 64,
            'timeout': 1,
            'socket': None,
            'incarnation': 0
        }
    socket_list=[]
    
    


    def __init__(self, family=-1, type=-1, proto=-1, fileno=None):
        self._log=logging.getLogger(__file__)
        super().__init__(family, type, proto, fileno)
       
        self.__ttl=None
        self._dst_address=None
        self._dst_port=None
        self._src_address=None
        self._src_port=None
        self._last_sent_bytes=None
        self._last_sent_flags=None
        self._last_error=None
        self._hops=[]
        self._last_send_time=None
        self._last_roundtrip_time=None
        self.settings={}
        self._total_sent_packets=0
        self._traceroute_running=False
        
        
        
    # @property
    # def src_port(self,port):
    #     self._src_port=port
    def check_for_config(self):
        if self._dst_address in self.global_settings: # specific supersedes global config
            dst=self._dst_address
        elif 'any' in self.global_settings:
            dst='any'
        else:
            return False
      

        if self._dst_port in self.global_settings[dst]: # specific supersedes global config
            dst_port=self._dst_port
        elif 'any' in self.global_settings[dst]:
            dst_port='any'
        else:
            return False
   

        if self._src_address in self.global_settings[dst][dst_port]: # specific supersedes global config
            src=self._src_address
        elif 'any' in self.global_settings[dst][dst_port]:
            src='any'
        else:
            return False

        if self._src_port in self.global_settings[dst][dst_port][src]: # specific supersedes global config
            src_port=self._src_address
        elif 'any' in self.global_settings[dst][dst_port][src]:
            src_port='any'
        else:
            return False

        self._log.debug(f"configuration for source {src}:{src_port} -> {dst}:{dst_port} found")

        # merge default config
        for k,v in self.default_settings.items():
            if k not in self.global_settings[dst][dst_port][src][src_port]:
                self.global_settings[dst][dst_port][src][src_port][k]=v

        self.settings=self.global_settings[dst][dst_port][src][src_port]
        self.__ttl=self.settings['initial_ttl']
        if self.settings['static_source_port']:
            self._src_port=int(self.settings['static_source_port'])
        self.settings['socket']=self
        self.settings['incarnation']+=1


    def bind_source_port(self):
        if self._src_port:
            try:
                if self._src_address:
                    self.bind((self._src_address,int(self._src_port)))
                    self._log.debug(f'Bound to static source port {self._src_address}:{self._src_port}')
                    
                else:
                    self.bind(('0.0.0.0',int(self._src_port)))
                    self._log.debug(f'Bound to static source port 0.0.0.0:{self._src_port}')
            except PermissionError as e:
                self._log.warning(f'Permission Denied. Cannot bind port {self._src_port} using ephermal port.')
                
        else:
            self._log.debug(f'No static source port defined using dynamic ephemeral port')
        
    def set_ttl(self,ttl):
        self._log.debug(f'Setting TTL to {ttl}')
        self.__ttl=ttl
        self.setsockopt(socket.SOL_IP, socket.IP_TTL, self.__ttl)
    
    def enable_error_handling(self):
        self.setsockopt(socket.IPPROTO_IP, IP_RECVERR, int(True))
        self.setsockopt (socket.SOL_IP, IP_RECVTTL, int(True))
        self._log.debug('Enabled IP_RECVERR and IP_RECVTTL flags on socket')

    def connect(self, __address):
        self._dst_address=__address[0]
        self._dst_port=__address[1]
        self.check_for_config()
        if not self.settings.get('enabled'):
            return super().connect(__address)
            
        self.bind_source_port()
        con=super().connect(__address)
        self._src_address, self._src_port=self.getsockname()
        self._log.debug(f'Opened connection from {self._src_address}:{self._src_port} to {self._dst_address}:{self._dst_port}')
        return con    

    def send(self,bytes,flags=0):
        if not self.settings.get('enabled'):
            return super().send(bytes,flags)
        if self.settings['auto_traceroute'] and not self._traceroute_running:
            if (self.settings['incarnation']-1) % int(self.settings['auto_traceroute']) == 0:
                self._log.debug(f'Auto traceroute enabled for {self.settings["auto_traceroute"] } incarnation of the socket.  Setting TTL=1 and timeout to {self.settings["timeout"]}')
                self.set_ttl(1)
                self.settimeout(self.settings['timeout'])
                self._traceroute_running=True
        
        self._log.debug(f'Sending {len(bytes)} bytes from {self._src_address}:{self._src_port} to {self._dst_address}:{self._dst_port}')
        if self.settings['debug'] == 'packet':
            hex_data=':'.join(format(c, '02x') for c in bytes)
            self._log.debug(f'Packet data: {hex_data}')
        self._last_sent_bytes=bytes
        self._last_sent_flags=flags
        self._last_error=None
        
        if self.settings['error_handling']:
            self.enable_error_handling()
        self._last_send_time=round(time.time() * 1000,2)
        result=super().send(bytes,flags)
        self._total_sent_packets+=1

        return result
   
    def sendto(self,bytes, address):
        self.connect(address)
        if not self.settings.get('enabled'):
            return super().sendto(bytes, address)        
        return  self.send(bytes)


    def get_network_hops(self):
        return self._socket_infos['hops']
    
    def handle_ancdata(self, ancdata):
        try: 
            if ancdata[0][1] == ERROR_REASON_ICMP:
                if len(ancdata) == 1:
                    reporting_ip = self._dst_address
                elif ancdata[1][2][ICMP_TYPE_OFFSET] == TTL_EXPIRED:
                    reporting_ip='.'.join([str(i) for i in ancdata[1][2][20:24]])
                    self._log.error (f'Got ICMP error TTL_EXPIRED from {reporting_ip} RTT {self._last_roundtrip_time} ms')
                    self._last_error='TTL_EXPIRED'
                    if self.__ttl == 1:
                        self._hops=[]
                elif ancdata[1][2][ICMP_TYPE_OFFSET] == DESTINATION_UNREACHABLE:
                    reporting_ip='.'.join([str(i) for i in ancdata[1][2][20:24]])
                    self._last_error='DESTINATION_UNREACHABLE'
                    self._log.error (f'got ICMP error DESTINATION_UNREACHABLE from {reporting_ip} RTT {self._last_roundtrip_time} ms')
                
        except Exception:
            self._log.error (f'Cannot parse ancdata {ancdata}')
        self._hops.append(
            [self.__ttl,reporting_ip,self._last_roundtrip_time]
        )            
        return reporting_ip


    def recv(self,max_packet_size):
        if not self.settings.get('enabled'):
            return super().recv(max_packet_size)
        self._last_roundtrip_time=round(time.time() * 1000 - self._last_send_time,4)
        try:
            data, ancdata, msg_flags, address = super().recvmsg(max_packet_size, 65535)
            self.handle_ancdata(ancdata)
        except OSError as e:
            data, ancdata, msg_flags, address = self.recvmsg(max_packet_size, 65535, MSG_ERRQUEUE)
            reporting_ip=self.handle_ancdata(ancdata)
            if self._last_error == 'TTL_EXPIRED':
                if self._traceroute_running:
                    self.set_ttl(self.__ttl+1)
                    self._log.debug(f'Auto traceroute enabled. Resending packet with TTL {self.__ttl}')                    
                    self.send(self._last_sent_bytes, self._last_sent_flags)
                    try:
                        return self.recv(max_packet_size)
                    except socket.timeout as e:
                        self._log.debug(f'Traceroute TTL {self.__ttl} timed out. Resending packet with TTL {self.__ttl+1}')
                        self._hops.append( [self.__ttl,"*","*"])
                        self.set_ttl(self.__ttl+1)
                        self.send(self._last_sent_bytes, self._last_sent_flags)
                        return self.recv(max_packet_size)

            elif self._last_error == 'DESTINATION_UNREACHABLE':
                self._traceroute_running=False
                raise DestinationUnreachable
        self._traceroute_running=False
        return data
    
    def recvfrom(self,max_packet_size):
        if not self.settings.get('enabled'):
            return super().recvfrom(max_packet_size)
        return (self.recv(max_packet_size),(self._dst_address,self._dst_port))

# register socketPlus
sys.modules['socket'].socket=DebugSocket

