# Copyright 2014 Andrey Danin
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import collectd
from pysnmp.entity.rfc3413.oneliner import ntforg
from threading import Thread


version = "0.0.1"
plugin_name = 'WallarmSNMPNotify'


class WallarmSNMPNotify(object):
    def __init__(self, plugin_name):
        self.plugin_name = plugin_name

        self.config = {
            'logging': {
                'enabled': False,
                'filename': '/tmp/wallarm_api_writer.log',
                'level': 'debug',
            },
            'configured': False,
        }

        self.dest_hosts = {
            '*/*': [
                {
                    'version': 'v2c',
                    'community': 'wallarm',
                    'secret': None,
                    'hostname': '127.0.0.1',
                    'port': 162,
                    'oid': '1.3.6.1.4.44332.1.1',
                },
            ],
        }

        self.logger = None

    def get_time(self):
        """
        Return the current time as epoch seconds.
        """

        return int(time.mktime(time.localtime()))

    def setup_logging(self):
        if ('logging' not in self.config or
                not self.config['logging'].get('enabled')):
            return
        logconfig = self.config['logging']
        logging.basicConfig(
            filename=logconfig['filename'],
            level=logging.getLevelName(logconfig['level'].upper()))
        self.logger = logging.getLogger()

    def log(self, level, msg):
        if level not in ('debug', 'info', 'notice', 'warning', 'error'):
            err_msg = 'Unknown log level {}. Change it to "info"'.format(level)
            self.logger and self.logger.info(err_msg)
            collectd.info(err_msg)
            level = 'info'

        if self.logger:
            getattr(self.logger, level)(msg)
        getattr(collectd, level)(msg)

    def get_dest_hosts(self, notification):
        # TODO(adanin) Implement a real filtering algorithm.
        return self.dest_hosts['*/*']

    def send_trap(self, host, notification):
        ntfOrg = ntforg.NotificationOriginator()
        errorIndication = ntfOrg.sendNotification(
            ntforg.CommunityData(host['community']),
            ntforg.UdpTransportTarget((host['hostname'], host['port'])),
            'trap',
            ntforg.MibVariable('SNMPv2-MIB', host['oid']),
            (ntforg.MibVariable('SNMPv2-MIB', 'sysName', 0), 'new name')
        )
        if errorIndication:
            self.log('info', 'Notification did not sent: %s' % errorIndication)

    def wallarm_snmp_notify(self, notification):
        hosts = self.get_dest_hosts()
        for host in hosts:
            thr = Thread(target=send_trap, args=(host, notification))
            thr.start()

    def wallarm_snmp_notify_config(self, cfg):
        # TODO(adanin) Add a real config parsing
        self.config['configured'] = True

    def wallarm_snmp_notify_init(self):
        if self.config['configured']:
            collectd.register_notification(self.wallarm_snmp_notify)
        else:
            self.log(
                'warning',
                'A configuration error occured. Abort initializing'
            )


plugin = WallarmSNMPNotify(plugin_name)
collectd.register_config(plugin.wallarm_snmp_notify_config)
collectd.register_init(plugin.wallarm_snmp_notify_init)
