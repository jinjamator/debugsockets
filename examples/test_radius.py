#!/usr/bin/env python

import os

import socket
import debugsockets
import radius
from pyzabbix import ZabbixMetric, ZabbixSender, ZabbixAPI 
import sys
import traceback
from time import sleep
from pprint import pprint

source_ip=None
source_port=None
port = os.environ.get('RADIUS_PORT',1812)
host= os.environ.get('RADIUS_SERVER','127.0.0.1')
secret=os.environ.get('RADIUS_SECRET','testing123')
username=os.environ.get('RADIUS_USERNAME','bob')
password=os.environ.get('RADIUS_PASSWORD','test')
interval=os.environ.get('RADIUS_INTERVAL',10)
static_source_port=os.environ.get('RADIUS_STATIC_SOURCE_PORT', False)

zbx_target=os.environ.get('ZABBIX_TARGET',host)
zbx_host_group=os.environ.get('ZABBIX_HOSTGROUP',"Radius Servers2")
zbx_base_key="app.radius.{}.{}"
zbx_username=os.environ.get('ZABBIX_USERNAME','Admin')
zbx_password=os.environ.get('ZABBIX_PASSWORD','zabbix')
zbx_url=os.environ.get('ZABBIX_URL','http://127.0.0.1')

zabbix_setup_done = False

socket.socket.global_settings[0]={
    'enabled': True,
    'debug': 'packet',
    'error_handling': True,
    'static_source_port':static_source_port,
    'initial_ttl':1,
    'auto_traceroute':2,
}


zbx_sender = ZabbixSender(
            os.environ.get('ZABBIX_SERVER','127.0.0.1'),
            os.environ.get('ZABBIX_PORT',10051)
        )

zbx = ZabbixAPI(zbx_url, user=zbx_username, password=zbx_password)
print(zbx.do_request('apiinfo.version'))


def setup_zabbix():
    global zbx_base_key
    global source_ip
    global source_port
    zbx_base_key=zbx_base_key.format(source_ip.replace('.','_'),source_port)
    try:
        group_id=zbx.hostgroup.get(filter={'name':zbx_host_group})[0].get('groupid')
    except IndexError:
        group_id=zbx.hostgroup.create(name=zbx_host_group)[0].get('groupids',[])[0]
    
    if not zbx.host.get(filter={'host':zbx_target}):
        zbx.host.create(host=zbx_target,groups=[zbx_host_group])
    zabbix_setup_done=True


def send_results(hop_list, auth_result, username, target_hostname):
    if not zabbix_setup_done:
        setup_zabbix()
    if auth_result:
        auth_result=1
    else:
        auth_result=0

    data=""
    metrics = []
    for result in hop_list:
        data+=f'{result[0]} {result[1]} {result[2]}(ms)\n'
    m = ZabbixMetric(target_hostname, f'{zbx_base_key}.traceroute', data)
    metrics.append(m)
    metrics.append(ZabbixMetric(target_hostname, '{zbx_base_key}.authentication.{username}', auth_result))
    zbx_sender.send(metrics)


while True:
    retval=False
    try:
        retval=radius.authenticate(secret, username, password, host=host, port=port)
    except radius.ChallengeResponse as e:
        print('Got Challange')
    except Exception as e:
        traceback.print_exc()
        print('Authentication Error')
    print()
    if retval:
        print(f'Authentication for user {username} successful')
    else:
        print(f'Authentication for user {username} failed')
    source_ip=socket.socket.socket_list[0]._src_address
    source_port=socket.socket.socket_list[0]._src_port
    send_results(socket.socket.socket_list[0]._hops,retval,username, zbx_target)
    print(f'Waiting for {interval} seconds')
    sleep(interval)