#!/usr/bin/python

# Copyright: Allen Smith <asmith687@t-mobile.com>
# License: MIT-0 (See https://opensource.org/license/mit-0)
from __future__ import absolute_import, division, print_function
from ansible.module_utils.basic import missing_required_lib

from collections import Counter
from yaml import safe_dump
from ipaddress import ip_address, ip_network

try:
    from requests import post, exceptions

    HAS_REQUESTS = True
except:
    HAS_REQUESTS = False

try:
    from requests_oauthlib import OAuth1Session

    HAS_REQUESTS_OAUTHLIB = True
except:
    HAS_REQUESTS_OAUTHLIB = False

SUBNET_SUPPORTED_KEYS = [
    "cidr",
    "description",
    "dns_servers",
    "gateway_ip",
    "name",
    "vid",
    "vlan",
    "id",
]
SUBNET_MODIFY_KEYS = ["description", "dns_servers", "gateway_ip", "name", "vid", "vlan"]

__metaclass__ = type

DOCUMENTATION = r"""
---
module: maas_subnets

short_description: Configure MAAS subnets

version_added: "1.0.0"

description: Configure MAAS subnets

options:
    password:
        description: Password for username used to get API token
        required: true
        type: str
    site:
        description: URL of the MAAS site (generally ending in /MAAS)
        required: true
        type: str
    state:
        description:
          - if C(absent) then the subnet(s) will be removed if currently present.
          - if C(present) then the subnet(s) will be created/updated.
          - if C(exact) then the resulting subnet list will match what is passed in.
        required: false
        type: str
        default: present
        choices: [ absent, present, exact ]
    username:
        description: Username to get API token for
        required: true
        type: str
    subnets:
        description: A list containing subnet specifier dictionaries
        required: true
        type: list
        suboptions:
          cidr:
              description: The CIDR address of the subnet
              required: true
              type: str
          dns_servers:
              description: List of DNS servers for this subnet
              required: false
              type: str
          description:
              description: The CIDR of the dest network
              required: true
              type: str
          gateway_ip:
              description: The gateway IP address
              required: true
              type: str
          vid:
              description: The VLAN ID of the subnet
              required: false
              type: int
          name:
              description: The name of the subnet
              required: false
              type: str

requirements:
   - requests
   - requests-oauthlib

author:
    - Allen Smith (@asmith-tmo)
"""

EXAMPLES = r"""
# Add/Remove as needed to exactly match given list
-  maas_subnets:
     username: user
     password: password
     state: exact
     subnets:
       - subnet_name: TESTNET
         description: TEST Network
         cidr: 10.23.1.0/24
         dns_servers: 192.168.1.53
         gateway_ip: 10.23.1.1
       - subnet_name: TESTNET101
         description: TEST Network V101
         cidr: 10.23.101.0/24
         dns_servers: 192.168.1.53
         gateway_ip: 10.23.101.1
         vid: 101
"""

RETURN = r"""
message:
    description: Status messages
    type: list
    returned: always
"""

from ansible.module_utils.basic import AnsibleModule


class maas_api_cred:
    """
    Represents a MAAS API Credenital
    Provides both MAAS API and OAuth terminology
    """

    def __init__(self, api_json):
        self.consumer_key = api_json["consumer_key"]
        self.token_key = api_json["token_key"]
        self.token_secret = api_json["token_secret"]

        self.client_key = self.consumer_key
        self.resource_owner_key = self.token_key
        self.resource_owner_secret = self.token_secret


def subnet_needs_updating(current, wanted, module):
    """
    Compare two subnet definitions and see if there are differences
    in the fields we allow to be changed
    """

    ret = False

    current_filtered = {k: v for k, v in current.items() if k in SUBNET_MODIFY_KEYS}
    wanted_filtered = {k: v for k, v in wanted.items() if k in SUBNET_MODIFY_KEYS}

    # We need to compare manually as wanted probably has vid, but current will have vlan.
    # SUBNET_MODIFY_KEYS = ["description", "dns_servers", "gateway_ip", "name", "vid", "vlan"]

    if wanted_filtered["description"] != current_filtered["description"]:
        ret = True

    if sorted(wanted_filtered["dns_servers"]) != sorted(
        current_filtered["dns_servers"]
    ):
        ret = True

    if wanted_filtered["gateway_ip"] != current_filtered["gateway_ip"]:
        ret = True

    if wanted_filtered["name"] != current_filtered["name"]:
        ret = True

    if str(wanted_filtered["vid"]) != str(current_filtered["vlan"]["vid"]):
        ret = True

    if str(wanted_filtered["vlan"]["vid"]) != str(current_filtered["vlan"]["vid"]):
        ret = True

    return ret


def get_maas_subnets(session, module):
    """
    Grab the current list of subnets
    """
    try:
        filtered_subnets = []
        current_subnets = session.get(f"{module.params['site']}/api/2.0/subnets/")
        current_subnets.raise_for_status()

        # filter the list down to keys we support
        for subnet in current_subnets.json():
            filtered_subnets.append(
                {k: v for k, v in subnet.items() if k in SUBNET_SUPPORTED_KEYS}
            )
        return filtered_subnets
    except exceptions.RequestException as e:
        module.fail_json(msg="Failed to get current subnet list: {}".format(str(e)))


def grab_maas_apikey(module):
    """
    Connect to MAAS API and grab the 3 part API key
    """
    consumer = "ansible@host"
    uri = "/accounts/authenticate/"
    site = module.params["site"]
    username = module.params["username"]
    password = module.params["password"]

    payload = {
        "username": username,
        "password": password,
        "consumer": consumer,
    }
    try:
        r = post(site + uri, data=payload)
        r.raise_for_status()
        return r
    except exceptions.RequestException as e:
        module.fail_json(msg="Auth failed: {}".format(str(e)))


def lookup_subnet(lookup, current_subnets, module):
    """
    Given a lookup return a subnet if the lookup
    matches a current subnet
    """
    if lookup["cidr"] in current_subnets.keys():
        return current_subnets[lookup["cidr"]]

    return None


def maas_add_subnets(session, current_subnets, module_subnets, module, res):
    """
    Given a list of subnets to add, we add those that don't exist
    If they exist, we check if something has changed and if it
    is a parameter that we can update, we call a function to do
    that.
    """
    subnetlist_added = []
    subnetlist_updated = []

    for subnet in module_subnets:
        if (matching_subnet := lookup_subnet(subnet, current_subnets, module)) is None:
            subnetlist_added.append(subnet)
            res["changed"] = True

            if not module.check_mode:
                payload = {
                    "cidr": subnet["cidr"],
                    "description": subnet["description"],
                    "dns_servers": ",".join(subnet["dns_servers"]),
                    "gateway_ip": subnet["gateway_ip"],
                    "name": subnet["name"],
                    "vid": subnet["vid"],
                }
                try:
                    r = session.post(
                        f"{module.params['site']}/api/2.0/subnets/",
                        data=payload,
                    )
                    r.raise_for_status()
                except exceptions.RequestException as e:
                    module.fail_json(
                        msg=f"subnet Add Failed: {format(str(e))} with payload {format(payload)} and {format(subnet)}"
                    )
        else:
            if subnet_needs_updating(matching_subnet, subnet, module):
                subnetlist_updated.append(subnet)
                res["changed"] = True

                subnet["id"] = matching_subnet["id"]

                if not module.check_mode:
                    payload = {
                        "description": subnet["description"],
                        "dns_servers": ",".join(subnet["dns_servers"]),
                        "gateway_ip": subnet["gateway_ip"],
                        "name": subnet["name"],
                        "vid": subnet["vid"],
                    }
                    try:
                        r = session.put(
                            f"{module.params['site']}/api/2.0/subnets/{subnet['id']}/",
                            data=payload,
                        )
                        r.raise_for_status()
                    except exceptions.RequestException as e:
                        module.fail_json(
                            msg=f"subnet Update Failed: {format(str(e))} with payload {format(payload)} and {format(subnet)}"
                        )

    new_subnets_dict = {
        item["cidr"]: item for item in get_maas_subnets(session, module)
    }

    res["diff"] = dict(
        before=safe_dump(current_subnets),
        after=safe_dump(new_subnets_dict),
    )

    if subnetlist_added:
        res["message"].append("Added subnets: " + str(subnetlist_added))

    if subnetlist_updated:
        res["message"].append("Updated subnets: " + str(subnetlist_updated))


def maas_delete_all_subnets(session, current_subnets, module, res):
    """
    Delete all subnets
    """
    subnetlist = []

    for item in current_subnets:
        subnet = current_subnets[item]
        subnetlist.append(item)
        res["changed"] = True

        if not module.check_mode:
            try:
                r = session.delete(
                    f"{module.params['site']}/api/2.0/subnets/{subnet['id']}/",
                )
                r.raise_for_status()
            except exceptions.RequestException as e:
                module.fail_json(
                    msg=f"subnet Remove Failed: {format(str(e))} with {format(current_subnets)}"
                )

            new_subnets_dict = {
                item["cidr"]: item for item in get_maas_subnets(session, module)
            }

            res["diff"] = dict(
                before=safe_dump(current_subnets),
                after=safe_dump(new_subnets_dict),
            )

    if subnetlist:
        res["message"].append("Removed subnets: " + str(subnetlist))


def maas_delete_subnets(session, current_subnets, module_subnets, module, res):
    """
    Given a list of subnets to remove, we delete those that exist"
    """
    subnetlist = []

    for subnet in module_subnets:
        if (
            matching_subnet := lookup_subnet(subnet, current_subnets, module)
        ) is not None:
            subnetlist.append(subnet["cidr"])
            res["changed"] = True

            subnet["id"] = matching_subnet["id"]

            if not module.check_mode:
                try:
                    r = session.delete(
                        f"{module.params['site']}/api/2.0/subnets/{subnet['id']}/",
                    )
                    r.raise_for_status()
                except exceptions.RequestException as e:
                    module.fail_json(
                        msg=f"subnet Remove Failed: {format(str(e))} with {format(current_subnets)}"
                    )

                new_subnets_dict = {
                    item["cidr"]: item for item in get_maas_subnets(session, module)
                }

                res["diff"] = dict(
                    before=safe_dump(current_subnets),
                    after=safe_dump(new_subnets_dict),
                )

    if subnetlist:
        res["message"].append("Removed subnets: " + str(subnetlist))


def maas_exact_subnets(session, current_subnets, module_subnets, module, res):
    """
    Given a list of subnets, remove and add/update as needed
    to make reality match the list
    """
    wanted = []
    delete_list = []

    module_subnets_dict = {k["cidr"]: k for k in module_subnets}

    wanted = module_subnets_dict.keys()

    delete_list = [
        current_subnets[subnet]
        for subnet in current_subnets.keys()
        if subnet not in wanted
    ]

    if delete_list:
        maas_delete_subnets(session, current_subnets, delete_list, module, res)

    if wanted:
        maas_add_subnets(session, current_subnets, module_subnets, module, res)


def run_module():
    module_args = dict(
        subnets=dict(type="list", required=True),
        password=dict(type="str", required=True, no_log=True),
        username=dict(type="str", required=True),
        site=dict(type="str", required=True),
        state=dict(type="str", required=False, default="present"),
    )

    result = dict(changed=False, message=[], diff={})

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    if not HAS_REQUESTS:
        module.fail_json(msg=missing_required_lib("requests"))

    if not HAS_REQUESTS_OAUTHLIB:
        module.fail_json(msg=missing_required_lib("requests_oauthlib"))

    validate_module_parameters(module)

    response = grab_maas_apikey(module)
    api_cred = maas_api_cred(response.json())

    maas_session = OAuth1Session(
        api_cred.client_key,
        resource_owner_key=api_cred.resource_owner_key,
        resource_owner_secret=api_cred.resource_owner_secret,
        signature_method="PLAINTEXT",
    )

    current_subnets_dict = {
        item["cidr"]: item for item in get_maas_subnets(maas_session, module)
    }

    if module.params["state"] == "present":
        maas_add_subnets(
            maas_session,
            current_subnets_dict,
            module.params["subnets"],
            module,
            result,
        )

    elif module.params["state"] == "absent":
        maas_delete_subnets(
            maas_session,
            current_subnets_dict,
            module.params["subnets"],
            module,
            result,
        )

    elif module.params["state"] == "exact":
        if module.params["subnets"]:
            maas_exact_subnets(
                maas_session,
                current_subnets_dict,
                module.params["subnets"],
                module,
                result,
            )
        else:
            maas_delete_all_subnets(
                maas_session,
                current_subnets_dict,
                module,
                result,
            )

    module.exit_json(**result)


def validate_module_parameters(module):
    """
    Perform simple validations on module parameters
    """

    subnets = module.params["subnets"]

    # Ensure we have all keys that we support modifying so that
    # We can easily compare and detect needed changes

    for subnet in subnets:
        if "cidr" not in subnet.keys():
            module.fail_json(msg="cidr is a required parameter, but not given.")

        if "vlan" in subnet.keys():
            subnet["vid"] = subnet["vlan"]["vid"]

        for key in SUBNET_MODIFY_KEYS:
            if key not in subnet.keys():
                if key == "dns_servers":
                    subnet[key] = []
                elif key == "vid":
                    subnet[key] = "0"
                elif key == "vlan":
                    if "vid" in subnet.keys():
                        subnet[key] = {"vid": subnet["vid"]}
                    else:
                        subnet[key] = {"vid": "0"}
                        subnet["vid"] = "0"
                else:
                    subnet[key] = ""

    # Validate IP related info
    for subnet in subnets:
        try:
            subnet_network = ip_network(subnet["cidr"])

        except ValueError as e:
            module.fail_json(msg="CIDR address given is invalid: {}".format(str(e)))

        try:
            for dns_server in subnet["dns_servers"]:
                dns_address = ip_address(dns_server)

        except ValueError as e:
            module.fail_json(msg="DNS address given is invalid: {}".format(str(e)))

        try:
            if subnet["gateway_ip"]:
                gateway_ip = ip_address(subnet["gateway_ip"])

                if gateway_ip not in subnet_network:
                    module.fail_json(
                        msg=f"The gateway IP given {gateway_ip} is not in the subnet {subnet_network}"
                    )

        except ValueError as e:
            module.fail_json(
                msg="Gateway IP address given is invalid: {}".format(str(e))
            )


def main():
    run_module()


if __name__ == "__main__":
    main()
