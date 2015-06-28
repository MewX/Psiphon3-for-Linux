#!/usr/bin/python
#
# Copyright (c) 2012, Psiphon Inc.
# All rights reserved.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#


from psi_api import Psiphon3Server
from psi_ssh_connection import SSHConnection, OSSHConnection
import json
import os
import subprocess
import optparse


DATA_FILENAME = 'psi_client.dat'
CLIENT_VERSION = 1
CLIENT_PLATFORM = 'Python'
SOCKS_PORT = 1080
LOCAL_HOST_IP = '127.0.0.1'
GLOBAL_HOST_IP = '0.0.0.0'


class Data(object):

    def __init__(self, data):
        self.data = data

    @staticmethod
    def load():
        try:
            with open(DATA_FILENAME, 'r') as data_file:
                data = Data(json.loads(data_file.read()))
            # Validate
            data.servers()[0]
            data.propagation_channel_id()
            data.sponsor_id()
        except (IOError, ValueError, KeyError, IndexError, TypeError) as error:
            print '\nPlease obtain a valid %s file and try again.\n' % (DATA_FILENAME,)
            raise
        return data

    def save(self):
        with open(DATA_FILENAME+'.new', 'w') as data_file:
            data_file.write(json.dumps(self.data))
        os.rename(DATA_FILENAME+'.new', DATA_FILENAME)

    def servers(self):
        return self.data['servers']

    def propagation_channel_id(self):
        return self.data['propagation_channel_id']

    def sponsor_id(self):
        return self.data['sponsor_id']

    def move_first_server_entry_to_bottom(self):
        servers = self.servers()
        if len(servers) > 1:
            servers.append(servers.pop(0))
            return True
        else:
            return False


def do_handshake(server, data, relay):

    handshake_response = server.handshake(relay)
    # handshake might update the server list with newly discovered servers
    data.save()
    return handshake_response


def print_sponsor_message(handshake_response):
    home_pages = handshake_response['Homepage']
    if len(home_pages) > 0:
        print '\nPlease visit our sponsor\'s homepage%s:' % ('s' if len(home_pages) > 1 else '',)
    for home_page in home_pages:
        print home_page
    print ''


def make_ssh_connection(server, relay, bind_all):

    if bind_all:
        listen_address=GLOBAL_HOST_IP
    else:
        listen_address=LOCAL_HOST_IP

    if relay == 'OSSH':
        ssh_connection = OSSHConnection(server, SOCKS_PORT, str(listen_address))
    elif relay == 'SSH':
        ssh_connection = SSHConnection(server, SOCKS_PORT, str(listen_address))
    else:
        assert False

    ssh_connection.connect()
    return ssh_connection


def connect_to_server(data, relay, bind_all, test=False):

    assert relay in ['SSH', 'OSSH']

    server = Psiphon3Server(data.servers(), data.propagation_channel_id(), data.sponsor_id(), CLIENT_VERSION, CLIENT_PLATFORM)

    if server.relay_not_supported(relay):
        raise Exception('Server does not support %s' % relay)

    handshake_performed = False
    if not server.can_attempt_relay_before_handshake(relay):
        handshake_response = do_handshake(server, data, relay)
        handshake_performed = True

    ssh_connection = make_ssh_connection(server, relay, bind_all)
    ssh_connection.test_connection()

    server.set_socks_proxy(SOCKS_PORT)

    if not handshake_performed:
        try:
            handshake_response = do_handshake(server, data, relay)
            handshake_performed = True
        except Exception as e:
            print 'DEBUG: handshake request: ' + str(e)

    connected_performed = False
    if handshake_performed:
        print_sponsor_message(handshake_response)
        try:
            server.connected(relay)
            connected_performed = True
        except Exception as e:
            print 'DEBUG: connected request: ' + str(e)

    if test:
        print 'Testing connection to ip %s' % server.ip_address
        ssh_connection.disconnect_on_success(test_site=test)
    else:
        print 'Press Ctrl-C to terminate.'
        try:
            ssh_connection.wait_for_disconnect()
        except KeyboardInterrupt as e:
            if connected_performed:
                try:
                    server.disconnected(relay)
                except Exception as e:
                    print 'DEBUG: disconnected request: ' + str(e)
            ssh_connection.disconnect()


def _test_executable(path):
    if os.path.isfile(path):
        try:
            with open(os.devnull, 'w') as devnull:
                subprocess.call(path, stdout=devnull, stderr=devnull)
                return True
        except OSError:
            pass
    return False


def connect(bind_all, test=False):

    while True:

        data = Data.load()

        try:
            relay = 'SSH'
            # NOTE that this path is also hard-coded in psi_ssh_connection
            ossh_path = './ssh'
            if _test_executable(ossh_path):
                relay = 'OSSH'
            else:
                print '%s is not a valid executable. Using standard ssh.' % (ossh_path,)

            connect_to_server(data, relay, bind_all, test)
            break
        except Exception as error:
            print 'DEBUG: %s connection: %s' % (relay, str(error))
            if test:
                break
            if not data.move_first_server_entry_to_bottom():
                print 'DEBUG: could not reorder servers'
                break
            data.save()
            print 'Trying next server...'


def test_all_servers(bind_all=False):

    data = Data.load()
    for _ in data.servers():
        connect(bind_all, test=True)
        print 'DEBUG: moving server to bottom'
        if not data.move_first_server_entry_to_bottom():
            print "could not reorder servers"
            break
        data.save()


if __name__ == "__main__":

    parser = optparse.OptionParser('usage: %prog [options]')
    parser.add_option("--expose", "-e", dest="expose",     
                        action="store_true", help="Expose SOCKS proxy to the network")
    parser.add_option("--test-servers", "-t", dest="test_servers",
                        action="store_true", help="Test all servers")
    (options, _) = parser.parse_args()
    
    if options.test_servers:
        test_all_servers()
    elif options.expose:
        connect(True)
    else:
        connect(False)
        

