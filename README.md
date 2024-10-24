## Zabbix Maintenance Script

Installation:

- Call role
- Create config file (e.g. `/etc/zabbix/zabbix_server-zabbix-maintenance.conf`):
    ```
    [DEFAULT]
    zabbix-api.user     = yourusername
    zabbix-api.password = yourpassword
    zabbix-api.url      = https://your.zabbix.host/
    ```
- Zabbix frontend -> Administration -> Scripts
    - Name: Maintenance/1h
    - Type: Script
    - Execute on: Zabbix server
    - Commands: `/opt/mit-zabbix-maintenance/bin/zabbix-maintenance.py -c /etc/zabbix/zabbix_server-zabbix-maintenance.conf -a set -l 60 -t {HOST.NAME} -i tmp-{USER.ALIAS}-{HOST.NAME}-1h`
    - Required host permissions: Read
    - Other fields: See [Zabbix Documentation](https://www.zabbix.com/documentation/current/manual/web_interface/frontend_sections/administration/scripts?s[]=scripts)