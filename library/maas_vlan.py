#!/usr/bin/python

# Copyright: Allen Smith <asmith687@t-mobile.com>
# License: MIT-0 (See https://opensource.org/license/mit-0)
from __future__ import absolute_import, division, print_function
from ansible.module_utils.basic import missing_required_lib

from collections import Counter
from yaml import safe_dump

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

VLAN_SUPPORTED_KEYS = ["mtu", "name", "vid"]
VLAN_MODIFY_KEYS = ["mtu", "name"]

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
        description:
          - if C(absent) then the vlan(s) will be removed if currently present.
          - if C(present) then the vlan(s) will be created/updated.
          - if C(exact) then the resulting vlan list will match what is passed in.
        required: false
        type: str
        default: present
        choices: [ absent, present, exact ]
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

requirements:
   - requests
   - requests-oauthlib

author:
    - Allen Smith (@asmith-tmo)
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

# Add/Remove as needed to exactly match given list
-  username: user
   password: password
   state: exact
   vlans:
     - name: 400
     - name: VLAN 500
       vid: 500

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


def vlan_needs_updating(current, wanted):
    """
    Compare two vlan definitions and see if there are differences
    in the fields we allow to be changed
    """
    ret = False
    current_filtered = {k: v for k, v in current.items() if k in VLAN_MODIFY_KEYS}
    wanted_filtered = {k: v for k, v in wanted.items() if k in VLAN_MODIFY_KEYS}

    for key in wanted_filtered.keys():
        if (key not in current_filtered.keys()) or (
            str(wanted_filtered[key]) != str(current_filtered[key])
        ):
            ret = True

    return ret


def get_maas_vlans(session, module):
    """
    Grab the current list of VLANs
    NOTE: We only support fabric 0 at this time so it is hard coded.
    """
    try:
        filtered_vlans = []
        current_vlans = session.get(f"{module.params['site']}/api/2.0/fabrics/0/vlans/")
        current_vlans.raise_for_status()

        # filter the list down to keys we support
        for vlan in current_vlans.json():
            filtered_vlans.append(
                {k: v for k, v in vlan.items() if k in VLAN_SUPPORTED_KEYS}
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


def maas_add_vlans(session, current_vlans, module_vlans, module, res):
    """
    Given a list of VLANs to add, we add those that don't exist
    If they exist, we check if something has changed and if it
    is a parameter that we can update, we call a function to do
    that.
    """
    vlist_added = []
    vlist_updated = []

    for vlan in module_vlans:
        wanted = {}
        wanted["name"] = vlan["name"]
        wanted["fabric_id"] = 0
        wanted["mtu"] = int(vlan["mtu"]) if "mtu" in vlan.keys() else 1500
        wanted["vid"] = int(vlan["vid"]) if "vid" in vlan.keys() else int(vlan["name"])

        if wanted["vid"] not in current_vlans.keys():
            vlist_added.append(wanted["vid"])
            res["changed"] = True

            if not module.check_mode:
                payload = {
                    "mtu": wanted["mtu"],
                    "name": wanted["name"],
                    "vid": wanted["vid"],
                    "fabric_id": wanted["fabric_id"],
                }
                try:
                    r = session.post(
                        f"{module.params['site']}/api/2.0/fabrics/{wanted['fabric_id']}/vlans/",
                        data=payload,
                    )
                    r.raise_for_status()
                except exceptions.RequestException as e:
                    module.fail_json(
                        msg=f"VLAN Add Failed: {format(str(e))} with payload {format(payload)} and {format(wanted)}"
                    )
        else:
            if vlan_needs_updating(current_vlans[wanted["vid"]], wanted):
                vlist_updated.append(wanted["vid"])
                res["changed"] = True

                if not module.check_mode:
                    payload = {
                        "mtu": wanted["mtu"],
                        "name": wanted["name"],
                    }
                    try:
                        r = session.put(
                            f"{module.params['site']}/api/2.0/fabrics/{wanted['fabric_id']}/vlans/{wanted['vid']}/",
                            data=payload,
                        )
                        r.raise_for_status()
                    except exceptions.RequestException as e:
                        module.fail_json(
                            msg=f"VLAN Update Failed: {format(str(e))} with payload {format(payload)} and {format(wanted)}"
                        )

    new_vlans_dict = {item["vid"]: item for item in get_maas_vlans(session, module)}

    res["diff"] = dict(
        before=safe_dump(current_vlans),
        after=safe_dump(new_vlans_dict),
    )

    if vlist_added:
        res["message"].append("Added vlans: " + str(vlist_added))

    if vlist_updated:
        res["message"].append("Updated vlans: " + str(vlist_updated))


def maas_delete_vlans(session, current_vlans, module_vlans, module, res):
    """
    Given a list of VLANs to remove, we delete those that exist"
    """
    vlist = []

    for vlan in module_vlans:
        fabric_id = 0
        vid = int(vlan["vid"]) if "vid" in vlan.keys() else int(vlan["name"])

        if vid in current_vlans.keys():
            vlist.append(vid)
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

    if vlist:
        res["message"].append("Removed vlans: " + str(vlist))


def maas_exact_vlans(session, current_vlans, module_vlans, module, res):
    """
    Given a list of VLANs, remove and add/update as needed
    to make reality match the list
    """
    wanted = []
    wanted_delete = []
    wanted_add_update = []

    for vlan in module_vlans:
        vlan["vid"] = int(vlan["vid"]) if "vid" in vlan.keys() else int(vlan["name"])
        wanted.append(vlan["vid"])

    module_vlans_dict = {k["vid"]: k for k in module_vlans}
    delete_list = [vid for vid in current_vlans.keys() if vid not in wanted]
    add_list = [vid for vid in wanted if vid not in current_vlans.keys()]
    update_list = [vid for vid in wanted if vid in current_vlans.keys()]

    delete_list.remove(0)

    if delete_list:
        wanted_delete = [{"name": k} for k in delete_list]
        maas_delete_vlans(session, current_vlans, wanted_delete, module, res)

    if add_list:
        wanted_add = [module_vlans_dict[k] for k in add_list]
        maas_add_vlans(session, current_vlans, wanted_add, module, res)

    if update_list:
        wanted_update = [module_vlans_dict[k] for k in update_list]
        maas_add_vlans(session, current_vlans, wanted_update, module, res)


def run_module():
    module_args = dict(
        vlans=dict(type="list", required=True),
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

    current_vlans_dict = {
        item["vid"]: item for item in get_maas_vlans(maas_session, module)
    }

    if module.params["state"] == "present":
        maas_add_vlans(
            maas_session, current_vlans_dict, module.params["vlans"], module, result
        )

    elif module.params["state"] == "absent":
        maas_delete_vlans(
            maas_session, current_vlans_dict, module.params["vlans"], module, result
        )

    elif module.params["state"] == "exact":
        maas_exact_vlans(
            maas_session, current_vlans_dict, module.params["vlans"], module, result
        )

    module.exit_json(**result)


def validate_module_parameters(module):
    """
    Perform simple validations on module parameters
    """
    vlans = module.params["vlans"]

    # Detect duplice vids
    vid_list = [vlan["vid"] if "vid" in vlan.keys() else vlan["name"] for vlan in vlans]
    if len(vid_list) != len(set(vid_list)):
        vlan_dupes = [item for item, count in Counter(vid_list).items() if count > 1]
        module.fail_json(
            msg=f"Duplicate vids handed to us in list of VLANs. Dupes are {vlan_dupes} from: {vlans}"
        )

    # Detect invalid vids
    invalid_vid_list = [
        vid for vid in vid_list if not type(vid) is int or (vid < 1 or vid > 4094)
    ]
    if len(invalid_vid_list):
        module.fail_json(msg=f"Invalid VIDs detected {invalid_vid_list} from: {vlans}")

    # Detect keys we don't yet handle
    for vlan in vlans:
        for key in vlan.keys():
            if key not in VLAN_SUPPORTED_KEYS:
                module.fail_json(
                    msg=f"{key} is not a supported key. Possible values {VLAN_SUPPORTED_KEYS}"
                )


def main():
    run_module()


if __name__ == "__main__":
    main()
