#!/usr/bin/env python

import os

import socket
import debugsockets
import radius
from pyzabbix import ZabbixMetric, ZabbixSender, ZabbixAPI, ZabbixAPIException 
import sys
import traceback
from time import sleep
from pprint import pprint





# socket.socket.global_settings[0]={
#     'enabled': True,
#     'debug': 'packet',
#     'error_handling': True,
#     'static_source_port':os.environ.get('RADIUS_STATIC_SOURCE_PORT', False),
#     'initial_ttl':1,
#     'auto_traceroute':2,
# }

source_port=os.environ.get('RADIUS_STATIC_SOURCE_PORT', False)

cfg={
    'enabled': True,
    'debug': 'packet',
    'error_handling': True,
    'auto_traceroute':2,
    'static_source_port': source_port
}


radius_port= os.environ.get('RADIUS_PORT',1812)
radius_server=os.environ.get('RADIUS_SERVER','127.0.0.1')
# dst,dst_port,src,src_port
# so hijack all sockets with dst ip of radius_server and radius port and set to static port source_port
socket.socket.global_settings[radius_server][radius_port]['any']['any']=cfg




class RadiusMonitoring(object):
    def __init__(self):
        self.zabbix_setup_done = False
        self.source_ip=None
        self.source_port=None
        self.port = int(os.environ.get('RADIUS_PORT',1812))
        self.host= os.environ.get('RADIUS_SERVER','127.0.0.1')
        self.secret=os.environ.get('RADIUS_SECRET','testing123')
        self.username=os.environ.get('RADIUS_USERNAME','bob')
        self.password=os.environ.get('RADIUS_PASSWORD','test')
        self.interval=int(os.environ.get('RADIUS_INTERVAL',10))
        self.static_source_port=int(os.environ.get('RADIUS_STATIC_SOURCE_PORT', False))
        self.zbx_target=os.environ.get('ZABBIX_TARGET',self.host)
        self.zbx_host_group=os.environ.get('ZABBIX_HOSTGROUP',"Radius Servers")
        self.zbx_base_key="app.radius.{}.{}"
        self.zbx_username=os.environ.get('ZABBIX_USERNAME','Admin')
        self.zbx_password=os.environ.get('ZABBIX_PASSWORD','zabbix')
        self.zbx_url=os.environ.get('ZABBIX_URL','http://127.0.0.1')
        self.zbx_sender_destination=os.environ.get('ZABBIX_SENDER_DESTINATION','127.0.0.1')
        self.zbx_sender_port=os.environ.get('ZABBIX_PORT',10051)
        self.zbx_sender = ZabbixSender(
                    self.zbx_sender_destination,
                    self.zbx_sender_port
                )
        self.zbx= None


    def setup_zabbix(self):
        self.zbx=ZabbixAPI(self.zbx_url, user=self.zbx_username, password=self.zbx_password)

        self.zbx_base_key=self.zbx_base_key.format(self.source_ip.replace('.','_'),self.source_port)
    
        # get/create hostgroup
        try:
            group_id=self.zbx.hostgroup.get(filter={'name':self.zbx_host_group})[0].get('groupid')
        except IndexError:
            group_id=self.zbx.hostgroup.create(name=self.zbx_host_group)[0].get('groupids',[])[0]
    
        # get/create host
        try:
            host_id=self.zbx.host.get(filter={'host':self.zbx_target})[0].get('hostid')
        except IndexError:
            host_id=self.zbx.host.create(host=self.zbx_target,groups=[{'groupid':group_id}]).get('hostids',[])[0]
        
        # create item 
        try:
            self.zbx.item.create(
                name=f"Authentication result user {self.username} from {self.source_ip}:{self.source_port}",
                key_=f"{self.zbx_base_key}.auth.{self.username}",
                hostid=host_id,
                type=2, # zabbix trapper
                value_type=3, # numeric unsigned
                tags=[{"tag":"Radius Authentication Result"}]
            )
        except ZabbixAPIException as e:
            if e.code == -32602: # item exists
                pass 

        try:
            self.zbx.item.create(
                name=f"Network hops from {self.source_ip}:{self.source_port}",
                key_=f"{self.zbx_base_key}.traceroute.hops",
                hostid=host_id,
                type=2, # zabbix trapper
                value_type=4, # numeric unsigned
                tags=[{"tag":"Network Hop List"}]
            )
        except ZabbixAPIException as e:
            if e.code == -32602: # item exists
                pass 

        try:
            self.zbx.item.create(
                name=f"Traceroute from {self.source_ip}:{self.source_port}",
                key_=f"{self.zbx_base_key}.traceroute.full",
                hostid=host_id,
                type=2, # zabbix trapper
                value_type=4, # numeric unsigned
                tags=[{"tag":"Traceroute"}]
            )
        except ZabbixAPIException as e:
            if e.code == -32602: # item exists
                pass 


        self.zabbix_setup_done=True


    def send_results(self,hops, auth_result, username, target_hostname):
        if not self.zabbix_setup_done:
            self.setup_zabbix()
        
        if auth_result:
            auth_result=1
        else:
            auth_result=0

        full_data=""
        hop_list=""
        metrics = []
        for result in hops:
            full_data+=f'{result[0]} {result[1]} {result[2]}(ms)\n'
            hop_list+=f'{result[0]} {result[1]}\n'

        m = ZabbixMetric(target_hostname, f"{self.zbx_base_key}.traceroute.full", full_data)
        metrics.append(m)
        m = ZabbixMetric(target_hostname, f"{self.zbx_base_key}.traceroute.hops", hop_list)
        metrics.append(m)

        metrics.append(ZabbixMetric(target_hostname, f'{self.zbx_base_key}.auth.{username}', auth_result))

        self.zbx_sender.send(metrics)

    def monitor(self):
        retval=False
        try:
            retval=radius.authenticate(self.secret, self.username, self.password, host=self.host, port=self.port)
        except radius.ChallengeResponse as e:
            print('Got Challange')
        except Exception as e:
            traceback.print_exc()
            print('Authentication Error')
        if retval:
            print(f'Authentication for user {self.username} successful')
        else:
            print(f'Authentication for user {self.username} failed')
        pprint(socket.socket.global_settings)
        sock=socket.socket.global_settings[radius_server][radius_port]['any']['any']['socket']
        print(sock._hops)
        self.source_ip=sock._src_address
        self.source_port=sock._src_port
        self.send_results(sock._hops,retval,self.username, self.zbx_target)
        print(f'Waiting for {self.interval} seconds')
        sleep(self.interval)
        # sock.__ttl=1

radmon = RadiusMonitoring()

while True:
    radmon.monitor()
