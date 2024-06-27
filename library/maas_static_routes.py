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

STATIC_ROUTE_SUPPORTED_KEYS = ["source", "destination", "gateway_ip", "metric", "id"]
STATIC_ROUTE_MODIFY_KEYS = ["source", "gateway_ip", "metric"]

__metaclass__ = type

DOCUMENTATION = r"""
---
module: maas_static_routes

short_description: Configure MAAS static_routes

version_added: "1.0.0"

description: Configure MAAS static_routes

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
          - if C(absent) then the static_route(s) will be removed if currently present.
          - if C(present) then the static_route(s) will be created/updated.
          - if C(exact) then the resulting static_route list will match what is passed in.
        required: false
        type: str
        default: present
        choices: [ absent, present, exact ]
    username:
        description: Username to get API token for
        required: true
        type: str
    static_routes:
        description: A list containing static_route specifier dictionaries
        required: true
        type: list
        suboptions:
          source:
              description: The CIDR of source network
              required: true
              type: str
          destination:
              description: The CIDR of the dest network
              required: true
              type: str
          gateway_ip:
              description: The gateway IP address
              required: true
              type: str
          metric:
              description: The weight of the route
              required: false
              type: int

notes:
   - The puppet code this is based on keys off the destination (assuming each destination
     is listed once) so this code does the same.

requirements:
   - requests
   - requests-oauthlib

author:
    - Allen Smith (@asmith-tmo)
"""

EXAMPLES = r"""
# Add/Remove as needed to exactly match given list
-  username: user
   password: password
   state: exact
   static_routes:
     - source: 10.23.1.0/24
       destination: 1.2.0.0/16
       gateway_ip: 10.23.1.1
     - source: 10.23.1.0/24
       destination: 192.168.66.0/24
       gateway_ip: 10.23.1.1
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


def static_route_needs_updating(current, wanted, module):
    """
    Compare two static_route definitions and see if there are differences
    in the fields we allow to be changed
    """

    ret = False
    current_filtered = {
        k: v for k, v in current.items() if k in STATIC_ROUTE_MODIFY_KEYS
    }
    wanted_filtered = {k: v for k, v in wanted.items() if k in STATIC_ROUTE_MODIFY_KEYS}

    # We need to compare manually as source may match name or cidr attributes
    if "metric" in wanted_filtered.keys():
        if str(wanted_filtered["metric"]) != str(current_filtered["metric"]):
            ret = True

    if wanted_filtered["gateway_ip"] != current_filtered["gateway_ip"]:
        ret = True

    if wanted_filtered["source"] not in (
        current_filtered["source"]["name"],
        current_filtered["source"]["cidr"],
    ):
        ret = True

    return ret


def get_maas_static_routes(session, module):
    """
    Grab the current list of static_routes
    """
    try:
        filtered_static_routes = []
        current_static_routes = session.get(
            f"{module.params['site']}/api/2.0/static-routes/"
        )
        current_static_routes.raise_for_status()

        # module.fail_json(msg=f"{current_static_routes.json()}")

        # filter the list down to keys we support
        for static_route in current_static_routes.json():
            filtered_static_routes.append(
                {
                    k: v
                    for k, v in static_route.items()
                    if k in STATIC_ROUTE_SUPPORTED_KEYS
                }
            )
        return filtered_static_routes
    except exceptions.RequestException as e:
        module.fail_json(
            msg="Failed to get current static_route list: {}".format(str(e))
        )


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


def lookup_static_route(lookup, current_sroutes, module):
    """
    Given a lookup return a static route if the lookup
    matches either the name or cidr property of a current route
    """

    for item in current_sroutes:
        if lookup in [
            current_sroutes[item]["destination"]["name"],
            current_sroutes[item]["destination"]["cidr"],
        ]:
            return current_sroutes[item]

    return None


def maas_add_static_routes(
    session, current_static_routes, module_static_routes, module, res
):
    """
    Given a list of static_routes to add, we add those that don't exist
    If they exist, we check if something has changed and if it
    is a parameter that we can update, we call a function to do
    that.
    """
    sroutelist_added = []
    sroutelist_updated = []
    matching_route = {}

    for static_route in module_static_routes:
        if (
            matching_route := lookup_static_route(
                static_route["destination"], current_static_routes, module
            )
        ) is None:

            sroutelist_added.append(static_route["destination"])
            res["changed"] = True

            if not module.check_mode:
                payload = {
                    "source": static_route["source"],
                    "destination": static_route["destination"],
                    "gateway_ip": static_route["gateway_ip"],
                    # "metric": static_route["metric"],
                }
                try:
                    r = session.post(
                        f"{module.params['site']}/api/2.0/static-routes/",
                        data=payload,
                    )
                    r.raise_for_status()
                except exceptions.RequestException as e:
                    module.fail_json(
                        msg=f"static_route Add Failed: {format(str(e))} with payload {format(payload)} and {format(static_route)}"
                    )
        else:
            if static_route_needs_updating(matching_route, static_route, module):
                sroutelist_updated.append(static_route["destination"])
                res["changed"] = True

                # module.fail_json(msg=f"{current_static_routes}")
                static_route["id"] = current_static_routes[static_route["destination"]][
                    "id"
                ]
                if not module.check_mode:
                    payload = {
                        "source": static_route["source"],
                        "gateway_ip": static_route["gateway_ip"],
                        # "metric": static_route["metric"],
                    }
                    try:
                        r = session.put(
                            f"{module.params['site']}/api/2.0/static-routes/{static_route['id']}/",
                            data=payload,
                        )
                        r.raise_for_status()
                    except exceptions.RequestException as e:
                        module.fail_json(
                            msg=f"static_route Update Failed: {format(str(e))} with payload {format(payload)} and {format(static_route)}"
                        )

    new_static_routes_dict = {
        item["destination"]["name"]: item
        for item in get_maas_static_routes(session, module)
    }

    res["diff"] = dict(
        before=safe_dump(current_static_routes),
        after=safe_dump(new_static_routes_dict),
    )

    if sroutelist_added:
        res["message"].append("Added static_routes: " + str(sroutelist_added))

    if sroutelist_updated:
        res["message"].append("Updated static_routes: " + str(sroutelist_updated))


def maas_delete_static_routes(
    session, current_static_routes, module_static_routes, module, res
):
    """
    Given a list of static_routes to remove, we delete those that exist"
    """
    vlist = []

    for static_route in module_static_routes:
        fabric_id = 0
        vid = (
            int(static_route["vid"])
            if "vid" in static_route.keys()
            else int(static_route["name"])
        )

        if vid in current_static_routes.keys():
            vlist.append(vid)
            res["changed"] = True

            if not module.check_mode:
                try:
                    r = session.delete(
                        f"{module.params['site']}/api/2.0/static-routes/{vid}/",
                    )
                    r.raise_for_status()
                except exceptions.RequestException as e:
                    module.fail_json(
                        msg=f"static_route Remove Failed: {format(str(e))} with {format(current_static_routes)}"
                    )

                new_static_routes_dict = {
                    item["vid"]: item
                    for item in get_maas_static_routes(session, module)
                }

                res["diff"] = dict(
                    before=safe_dump(current_static_routes),
                    after=safe_dump(new_static_routes_dict),
                )

    if vlist:
        res["message"].append("Removed static_routes: " + str(vlist))


def maas_exact_static_routes(
    session, current_static_routes, module_static_routes, module, res
):
    """
    Given a list of static_routes, remove and add/update as needed
    to make reality match the list
    """
    wanted = []
    wanted_delete = []
    wanted_add_update = []

    for static_route in module_static_routes:
        static_route["vid"] = (
            int(static_route["vid"])
            if "vid" in static_route.keys()
            else int(static_route["name"])
        )
        wanted.append(static_route["vid"])

    module_static_routes_dict = {k["vid"]: k for k in module_static_routes}
    delete_list = [vid for vid in current_static_routes.keys() if vid not in wanted]
    add_list = [vid for vid in wanted if vid not in current_static_routes.keys()]
    update_list = [vid for vid in wanted if vid in current_static_routes.keys()]

    delete_list.remove(0)

    if delete_list:
        wanted_delete = [{"name": k} for k in delete_list]
        maas_delete_static_routes(
            session, current_static_routes, wanted_delete, module, res
        )

    if add_list:
        wanted_add = [module_static_routes_dict[k] for k in add_list]
        maas_add_static_routes(session, current_static_routes, wanted_add, module, res)

    if update_list:
        wanted_update = [module_static_routes_dict[k] for k in update_list]
        maas_add_static_routes(
            session, current_static_routes, wanted_update, module, res
        )


def run_module():
    module_args = dict(
        static_routes=dict(type="list", required=True),
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

    # validate_module_parameters(module)

    response = grab_maas_apikey(module)
    api_cred = maas_api_cred(response.json())

    maas_session = OAuth1Session(
        api_cred.client_key,
        resource_owner_key=api_cred.resource_owner_key,
        resource_owner_secret=api_cred.resource_owner_secret,
        signature_method="PLAINTEXT",
    )

    # We need to key on both of these. Probably more pythonic ways
    # of doing this.

    current_static_routes_dict = {
        item["destination"]["name"]: item
        for item in get_maas_static_routes(maas_session, module)
    }

    # module.fail_json(msg=f"{current_static_routes_dict}")

    if module.params["state"] == "present":
        maas_add_static_routes(
            maas_session,
            current_static_routes_dict,
            module.params["static_routes"],
            module,
            result,
        )

    elif module.params["state"] == "absent":
        maas_delete_static_routes(
            maas_session,
            current_static_routes_dict,
            module.params["static_routes"],
            module,
            result,
        )

    elif module.params["state"] == "exact":
        maas_exact_static_routes(
            maas_session,
            current_static_routes_dict,
            module.params["static_routes"],
            module,
            result,
        )

    module.exit_json(**result)


def validate_module_parameters(module):
    """
    Perform simple validations on module parameters
    """
    static_routes = module.params["static_routes"]

    # Detect duplice vids
    vid_list = [
        static_route["vid"] if "vid" in static_route.keys() else static_route["name"]
        for static_route in static_routes
    ]
    if len(vid_list) != len(set(vid_list)):
        static_route_dupes = [
            item for item, count in Counter(vid_list).items() if count > 1
        ]
        module.fail_json(
            msg=f"Duplicate vids handed to us in list of static_routes. Dupes are {static_route_dupes} from: {static_routes}"
        )

    # Detect invalid vids
    invalid_vid_list = [
        vid for vid in vid_list if not type(vid) is int or (vid < 1 or vid > 4094)
    ]
    if len(invalid_vid_list):
        module.fail_json(
            msg=f"Invalid VIDs detected {invalid_vid_list} from: {static_routes}"
        )

    # Detect keys we don't yet handle
    for static_route in static_routes:
        for key in static_route.keys():
            if key not in STATIC_ROUTE_SUPPORTED_KEYS:
                module.fail_json(
                    msg=f"{key} is not a supported key. Possible values {STATIC_ROUTE_SUPPORTED_KEYS}"
                )


def main():
    run_module()


if __name__ == "__main__":
    main()
