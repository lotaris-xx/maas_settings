#!/usr/bin/python

# Copyright: Allen Smith <asmith687@t-mobile.com>
# License: MIT-0 (See https://opensource.org/license/mit-0)
from __future__ import absolute_import, division, print_function

from collections import Counter
from requests import post, exceptions
from requests_oauthlib import OAuth1Session
from yaml import safe_dump

__metaclass__ = type

DOCUMENTATION = r"""
---
module: maas_vlan

short_description: Configure MAAS vlans

version_added: "1.0.0"

description: Configure MAAS vlans

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
        description: A list containing vlan specifier dictionaries
        required: false
        type: str
        default: present
        choices:
            - absent
            - present
    username:
        description: Username to get API token for
        required: true
        type: str
    vlans:
        description: A list containing vlan specifier dictionaries
        required: true
        type: list
        suboptions:
          mtu:
              description: The MTU of the vlan
              required: false
              default: 1500
              type: str
          name:
              description: The name of the vlan
              required: true
              type: str
          vid:
              description: VLAN ID (defaults to O(name))
              required: false
              default: O(name)
              type: str

notes:
   - The API accepts more options for O(vlans) list members
     however only those mentioned are supported by this
     module.

# Specify this value according to your collection
# in format of namespace.collection.doc_fragment_name
# extends_documentation_fragment:
#     - my_namespace.my_collection.my_doc_fragment_name

author:
    - Allen Smith (@allsmith-tmo)
"""

EXAMPLES = r"""
# Add 3 vlans if they don't exist
-  username: user
   password: password
   vlans:
     - name: 100
     - name: 200
     - name: 300

# Remove two vlans if they exist
-  username: user
   password: password
   state: absent
   vlans:
     - name: 200
     - name: 300
"""

RETURN = r"""
# These are examples of possible return values, and in general should use other names for return values.
message:
    description: A status message from the module
    type: str
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


def get_maas_vlans(session, module):
    """
    Grab the current list of VLANs
    NOTE: We really only support fabric 0 at this time so it is hard coded.
    """
    try:
        filtered_vlans = []
        current_vlans = session.get(f"{module.params['site']}/api/2.0/fabrics/0/vlans/")
        current_vlans.raise_for_status()

        # filter the list down to keys we support
        for vlan in current_vlans.json():
            filtered_vlans.append(
                {k: v for k, v in vlan.items() if k in vlan_supported_keys}
            )
        return filtered_vlans
    except exceptions.RequestException as e:
        module.fail_json(msg="Failed to get current VLAN list: {}".format(str(e)))


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


def maas_add_vlans(session, current_vlans, module, res):
    """
    Given a list of VLANs to add, we add those that don't exist
    """
    vlist = []

    for vlan in module.params["vlans"]:
        fabric_id = int(vlan["fabric_id"]) if "fabric_id" in vlan.keys() else "0"
        mtu = int(vlan["mtu"]) if "mtu" in vlan.keys() else "1500"
        vid = int(vlan["vid"]) if "vid" in vlan.keys() else int(vlan["name"])

        if vid not in current_vlans.keys():
            vlist.append(vlan["name"])
            res["changed"] = True

            if not module.check_mode:
                payload = {
                    "mtu": mtu,
                    "name": vlan["name"],
                    "vid": vid,
                    "fabric_id": fabric_id,
                }
                try:
                    r = session.post(
                        f"{module.params['site']}/api/2.0/fabrics/{fabric_id}/vlans/",
                        data=payload,
                    )
                    r.raise_for_status()
                except exceptions.RequestException as e:
                    module.fail_json(
                        msg=f"VLAN Add Failed: {format(str(e))} with payload {format(payload)} and {format(current_vlans)}"
                    )

                new_vlans_dict = {
                    item["vid"]: item for item in get_maas_vlans(session, module)
                }

                res["diff"] = dict(
                    before=safe_dump(current_vlans),
                    after=safe_dump(new_vlans_dict),
                )

        res["message"] = "Added vlans " + str(vlist)


def maas_delete_vlans(session, current_vlans, module, res):
    """
    Given a list of VLANs to remove, we delete those that exist"
    """
    vlist = []

    for vlan in module.params["vlans"]:
        fabric_id = int(vlan["fabric_id"]) if "fabric_id" in vlan.keys() else 0
        vid = int(vlan["vid"]) if "vid" in vlan.keys() else int(vlan["name"])

        if vid in current_vlans.keys():
            vlist.append(vlan["name"])
            res["changed"] = True

            if not module.check_mode:
                try:
                    r = session.delete(
                        f"{module.params['site']}/api/2.0/fabrics/{fabric_id}/vlans/{vid}/",
                    )
                    r.raise_for_status()
                except exceptions.RequestException as e:
                    module.fail_json(
                        msg=f"VLAN Remove Failed: {format(str(e))} with {format(current_vlans)}"
                    )

                new_vlans_dict = {
                    item["vid"]: item for item in get_maas_vlans(session, module)
                }

                res["diff"] = dict(
                    before=safe_dump(current_vlans),
                    after=safe_dump(new_vlans_dict),
                )

    res["message"] = "Removed vlans " + str(vlist)


def run_module():
    module_args = dict(
        vlans=dict(type="list", required=True),
        password=dict(type="str", required=True, no_log=True),
        username=dict(type="str", required=True),
        site=dict(type="str", required=True),
        state=dict(type="str", required=False, default="present"),
    )

    result = dict(changed=False, message={}, diff={})

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    globals()["vlan_supported_keys"] = ["mtu", "name", "vid"]

    validate_module_parameters(module)

    r = grab_maas_apikey(module)
    c = maas_api_cred(r.json())

    maas_session = OAuth1Session(
        c.client_key,
        resource_owner_key=c.resource_owner_key,
        resource_owner_secret=c.resource_owner_secret,
        signature_method="PLAINTEXT",
    )

    current_vlans_dict = {
        item["vid"]: item for item in get_maas_vlans(maas_session, module)
    }

    if module.params["state"] == "present":
        maas_add_vlans(maas_session, current_vlans_dict, module, result)

    elif module.params["state"] == "absent":
        maas_delete_vlans(maas_session, current_vlans_dict, module, result)

    module.exit_json(**result)


def validate_module_parameters(module):
    """
    Perform simple validations on module parameters
    """
    vlans = module.params["vlans"]

    vid_list = [vlan["vid"] if "vid" in vlan.keys() else vlan["name"] for vlan in vlans]
    vid_list_set = set(vid_list)
    if len(vid_list) != len(vid_list_set):
        vlan_dupes = [item for item, count in Counter(vid_list).items() if count > 1]
        module.fail_json(
            f"msg=Duplicate vids handed to us in list of VLANs. Dupes are {vlan_dupes} from: {vlans}"
        )

    for vlan in vlans:
        for key in vlan.keys():
            if key not in vlan_supported_keys:
                module.fail_json(
                    f"msg={key} is not in supported keys. Possible values {vlan_supported_keys}"
                )


def main():
    run_module()


if __name__ == "__main__":
    main()
