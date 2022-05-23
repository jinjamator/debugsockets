#!/usr/bin/env python

import os
import socket
import debugsockets
import radius
import sys
import traceback
# from zbxsend import Metric, send_to_zabbix 
from time import sleep

socket.socket._settings['debug']='packet'
socket.socket._settings['error_handling']=True
socket.socket._settings['static_source_port']=10000
socket.socket._settings['initial_ttl']=1
socket.socket._settings['auto_traceroute']=2
while True:
    port = os.environ.get('RADIUS_PORT',1812)
    host= os.environ.get('RADIUS_SERVER','127.0.0.1')
    secret=os.environ.get('RADIUS_SECRET','testing123')
    username=os.environ.get('RADIUS_USERNAME','bob')
    password=os.environ.get('RADIUS_PASSWORD','test')
    interval=os.environ.get('RADIUS_INTERVAL',10)
    retval=False
    try:
        retval=radius.authenticate(secret, username, password, host=host, port=port)
    except radius.ChallengeResponse as e:
        print('Got Challange')
    except Exception as e:
        traceback.print_exc()
        print('Authentication Error')

    if retval:
        # send_to_zabbix([Metric('localhost', 'bucks_earned', 99999)], 'localhost', 10051)
        print(f'Authentication for user {username} successful')
    else:
        print(f'Authentication for user {username} failed')
    print(f'Waiting for {interval} seconds')
    sleep(interval)