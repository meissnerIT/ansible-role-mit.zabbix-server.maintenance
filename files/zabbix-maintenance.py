#!/opt/mit-zabbix-maintenance/.venv/bin/python
# -*- coding: utf-8 -*-
#
# Distributed via ansible - mit.zabbix-server.maintenance
#
# #20771: Zabbix Maintenance Skript
# Based on https://github.com/RafPe/hubot-zabbix-scripts
#
# v2024-02-14 by markus.meissner@meissner.IT
# v2024-10-24: Switched to pyzabbix, not all features are changed / tested

import argparse
import configparser
import datetime
import logging
import os
import sys
import time
import uuid

import urllib3
from pyzabbix import ZabbixAPI

formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
shStdout = logging.StreamHandler(sys.stdout)
shStdout.setFormatter(formatter)
shStderr = logging.StreamHandler(sys.stderr)
shStderr.setFormatter(formatter)
shStderr.setLevel(logging.ERROR)
log = logging.getLogger(os.path.basename(__file__))
log.addHandler(shStdout)
log.addHandler(shStderr)
log.setLevel(logging.INFO)
# log.setLevel(logging.DEBUG)


__author__ = "RafPe"

parser = argparse.ArgumentParser(description="This is a demo script by RafPe.")
parser.add_argument(
    "-c", "--config", help="Config file for user / password", required=False
)
parser.add_argument("-u", "--user", help="Zabbix user name", required=False)
parser.add_argument("-p", "--password", help="Zabbix user password", required=False)
parser.add_argument("-t", "--target", help="Zabbix target host/group", required=False)
parser.add_argument("-s", "--server", help="Zabbix server", required=False)
parser.add_argument("-a", "--action", help="Action to be taken", required=True)
parser.add_argument("-l", "--length", help="Maintanance length", required=False)
parser.add_argument(
    "-d", "--desc", help="Maintanance description", required=False, default=""
)
parser.add_argument(
    "-r", "--requestor", help="Maintanance requested by", required=False
)
parser.add_argument("-i", "--id", help="Maintanance uuid", required=False)
parser.add_argument("-v", "--verbose", help="Be verbose", required=False)
args = parser.parse_args()


def create_maintenance(
    zbx, group_ids, host_ids, start_time, maintenance_type, period, name, desc
):
    end_time = start_time + period
    try:
        res = zbx.maintenance.create(
            {
                "groupids": group_ids,
                "hostids": host_ids,
                "name": name,
                "maintenance_type": maintenance_type,
                "active_since": int(start_time),
                "active_till": int(end_time),
                "description": str(desc),
                "timeperiods": [
                    {
                        "timeperiod_type": "0",
                        "start_date": int(start_time),
                        "period": int(period),
                    }
                ],
            }
        )
    except BaseException as e:
        print(e)
        return None

    referenceids = ", ".join(str(x) for x in res["maintenanceids"])

    print(
        "Success! Created maintanance for %s groups/%s hosts with name '%s'"
        % (
            len(group_ids) if group_ids else "0",
            len(host_ids) if host_ids else "0",
            name,
        )
    )
    print("Reference IDs: %s " % referenceids)

    return "Maintenance created"


def get_maintenance_id_by_id(zbx, name):
    result = zbx.maintenance.get(filter={"name": name})
    maintenance_ids = []
    for res in result:
        maintenance_ids.append(res["maintenanceid"])
    return maintenance_ids


def delete_maintenance(zbx, maintenance_id):
    try:
        zbx.maintenance.delete(maintenance_id)
        # print "nothing to watch here - would delete %s" % maintenance_id
        print("Maintanance %s has been deleted" % maintenance_id)
    except BaseException:
        return None
    return "Done!"


def get_group_id(zbx, host_group):
    log.debug(f"get_group_id(zbx, {host_group})")
    if '"' in host_group:
        host_group = host_group.replace('"', "")

    # Issue:1 whitespace in groups/hosts
    host_group = host_group.strip(" \n\t\r")

    result = zbx.hostgroup.get(filter={"name": host_group})

    if not result:
        return None

    return result[0]["groupid"]


def get_host_id(zapi, host_names):
    if '"' in host_names:
        host_names = host_names.replace('"', "")

    # Issue:1 whitespace in groups/hosts
    host_names = host_names.strip(" \n\t\r")

    result = zapi.host.get(filter={"host": host_names})
    if not result:
        return None
    log.debug("Search({}): {}".format(host_names, result))
    return result[0]["hostid"]


def main():
    if args.config:
        configParser = configparser.RawConfigParser()
        configFilePath = args.config
        configParser.read(configFilePath)
        login_user = configParser.get("DEFAULT", "zabbix-api.user")
        # login_password = configParser.get('DEFAULT', 'zabbix-api.password')
        server_url = configParser.get("DEFAULT", "zabbix-api.url")
        # validate_certs = configParser.getboolean('DEFAULT', 'zabbix-api.validate_certs')
        log.debug("Got user=%s, url=%s from %s" % (login_user, server_url, args.config))
    else:
        login_user = args.user
        # login_password      = args.password
        server_url = args.server

    # host_names          = args.target
    # host_groups         = args.target
    target = args.target
    state = args.action
    # http_login_user = args.user
    # http_login_password = args.password
    # requestor = args.requestor
    minutes = args.length
    if args.id:
        name = "%s-%s" % (
            args.id,
            datetime.datetime.now().replace(microsecond=0).isoformat(),
        )
    else:
        name = "bender:%s" % uuid.uuid4()
    desc = args.desc
    collect_data = 1  # Need to variableize this :)
    # timeout = 5

    # Havent yet created param for this
    if collect_data:
        maintenance_type = 0
    else:
        maintenance_type = 1

    ##############################################################################
    # mit-pyzabbix.py v2023-09-20
    ##############################################################################
    # https://github.com/lukecyca/pyzabbix/issues/157
    # detect_version=False only needed for pyzabbix < 1.3
    zapi = ZabbixAPI(configParser.get("DEFAULT", "zabbix-api.url"))
    if configParser.has_option("DEFAULT", "zabbix-api.verify"):
        # https://requests.readthedocs.io/en/master/user/advanced/#ssl-cert-verification
        zapi.session.verify = configParser.get("DEFAULT", "zabbix-api.verify")
    elif not configParser.getboolean(
        "DEFAULT", "zabbix-api.certificate_verification", fallback=True
    ):
        # https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings
        urllib3.disable_warnings()
        zapi.session.verify = False
        log.info(
            "Disabled certificate verification - please don't use this in production!"
        )

    # https://requests.readthedocs.io/en/latest/user/advanced/#proxies
    if configParser.has_option("DEFAULT", "zabbix-api.proxy"):
        proxies = {
            "http": configParser.get("DEFAULT", "zabbix-api.proxy"),
            "https": configParser.get("DEFAULT", "zabbix-api.proxy"),
        }
        zapi.session.proxies.update(proxies)

    zapi.login(
        configParser.get("DEFAULT", "zabbix-api.user"),
        configParser.get("DEFAULT", "zabbix-api.password"),
    )
    log.debug("Connected to Zabbix API Version %s" % zapi.api_version())

    # zbx = zapi

    if state == "set":
        now = datetime.datetime.now()
        start_time = int(time.mktime(now.timetuple()))
        period = 60 * int(args.length)  # N * 60 seconds

        # Defined our array for group IDs
        group_ids = []
        host_ids = []

        result = None

        # Query for groups
        if "," in target:
            for group in target.strip().split(","):
                result = get_group_id(zapi, group)
                if result:
                    group_ids.append(result)
        else:
            result = get_group_id(zapi, target)
            if result:
                group_ids.append(result)

        # Query for hosts
        if "," in target:
            for host in target.strip().split(","):
                result = get_host_id(zapi, host)
                if result:
                    host_ids.append(result)
        else:
            result = get_host_id(zapi, target)
            if result:
                host_ids.append(result)

        ## info
        # print("Helping out *@%s* to be quiet as ninja when working :) " % requestor)
        # print("host_names          = %s" % host_names)
        # print("host_groups         = %s" % host_groups)
        print("host                = '%s'" % target)
        print("minutes             = %s" % minutes)
        print("name/id             = %s" % name)
        # print("desc                = %s" % desc)
        # print("collect_data        = %s" % collect_data)
        # print("timeout             = %s" % timeout)
        # print("requestor           = %s" % requestor)
        print("Found %s group(s) / %s host(s) " % (len(group_ids), len(host_ids)))

        maintenance = get_maintenance_id_by_id(zapi, name)

        if not maintenance:
            if not host_ids and not group_ids:
                print(
                    "At least one host/host group must be defined/found to create maintenance."
                )
                return

            outcome = create_maintenance(
                zapi,
                group_ids,
                host_ids,
                start_time,
                maintenance_type,
                period,
                name,
                desc,
            )
            if not outcome:
                print("Failed to create maintenance")

        else:
            print("Maintanance already exists : %s" % maintenance)

    elif state == "del":
        maintenance = get_maintenance_id_by_id(zapi, name)

        if not maintenance:
            print("No maintanance(s) have been found with name %s" % name)
            return
        else:
            delete_maintenance(zapi, maintenance)

    else:
        print("Not implemented in this version yet :/ ")


if __name__ == "__main__":
    main()
