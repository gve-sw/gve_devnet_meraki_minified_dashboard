#!/usr/bin/env python3
"""
Copyright (c) 2023 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at
https://developer.cisco.com/docs/licenses
All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""

__author__ = "Trevor Maco <tmaco@cisco.com>, Rey Diaz <rediaz@cisco.com>"
__copyright__ = "Copyright (c) 2023 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.1"

# Import Section
import datetime
import json
import os
import pprint
import re
import logging
from logging.handlers import TimedRotatingFileHandler

import meraki
import requests
from dotenv import load_dotenv
from flask import Flask, render_template, request, url_for, redirect

import config

# Global variables
app = Flask(__name__)

# Note: these are lists of indoor and outdoor ap's at the time of writing, please update if a newer/older model is
# not present in the appropriate list
indoor_aps = ['MR16', 'MR18', 'MR20', 'MR28', 'CW9162', 'CW9164', 'CW9166', 'MR36H', 'MR20', 'MR44', 'MR46', 'MR30H',
              'MR36', 'MR46E', 'MR52', 'MR56', 'MR57']
outdoor_aps = ['MR78', 'MR70', 'MR76', 'MR86']

# Load in Environment Variables
load_dotenv()
MERAKI_API_KEY = os.getenv('MERAKI_API_KEY')

# Meraki Dashboard Instance
dashboard = meraki.DashboardAPI(api_key=MERAKI_API_KEY, suppress_logging=True)

# Set up logging
logger = logging.getLogger('my_logger')
logger.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s %(levelname)s: %(funcName)s:%(lineno)d - %(message)s')

# log to stdout
stream_handler = logging.StreamHandler()
stream_handler.setLevel(logging.INFO)
stream_handler.setFormatter(formatter)

# log to files (last 7 days, rotated at midnight local time each day)
log_file = "./logs/portal_logs.log"
file_handler = TimedRotatingFileHandler(log_file, when="midnight", interval=1, backupCount=7)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(stream_handler)

pp = pprint.PrettyPrinter(indent=4)

# One time actions
ORGANIZATIONS = dashboard.organizations.getOrganizations()

# Load in RADIUS servers for SSIDs
with open(config.RADIUS_SERVERS, 'r') as fp:
    RADIUS_SERVERS = json.load(fp)

# Build drop down menus for organization and network selection (the available options in the left hand menu bar)
DROPDOWN_CONTENT = []
for organization in ORGANIZATIONS:
    org_data = {'orgaid': organization['id'], 'organame': organization['name']}
    try:
        networks = dashboard.organizations.getOrganizationNetworks(organization['id'])
        network_data = [{'networkid': network['id'], 'networkname': network['name']} for network in networks]
        org_data['networks'] = network_data
        DROPDOWN_CONTENT.append(org_data)
    except Exception as e:
        logger.error(f"Error retrieving networks for organization ID {organization['id']}: {e}")


# Methods
def getSystemTimeAndLocation():
    """
    Return location and time of accessing device (used on all webpage footers)
    :return:
    """
    # request user ip
    userIPRequest = requests.get('https://get.geojs.io/v1/ip.json')
    userIP = userIPRequest.json()['ip']

    # request geo information based on ip
    geoRequestURL = 'https://get.geojs.io/v1/ip/geo/' + userIP + '.json'
    geoRequest = requests.get(geoRequestURL)
    geoData = geoRequest.json()

    # create info string
    location = geoData['country']
    timezone = geoData['timezone']
    current_time = datetime.datetime.now().strftime("%d %b %Y, %I:%M %p")
    timeAndLocation = "System Information: {}, {} (Timezone: {})".format(location, current_time, timezone)

    return timeAndLocation


# Routes
@app.route('/')
def index():
    """
    Main landing page, displays org summary and high level network information tables populated with the latest data.
    :return: Renders index.html
    """
    error_code = None

    selected_organization = request.form.get('organizations_select')
    selected_network = request.form.get('networks_select')

    logger.info('Main Index Page Request')
    logger.info("Selected Organization: %s", selected_organization)
    logger.info("Selected Network: %s", selected_network)

    selected_elements = {
        'organization': selected_organization,
        'network_id': selected_network
    }

    # Build list of networks/orgs (for display)
    network_displays = []
    org_displays = []
    for org in ORGANIZATIONS:
        try:
            # Get a list of org networks
            networks = dashboard.organizations.getOrganizationNetworks(org['id'], total_pages='all')
        except Exception as e:
            error_code = e
            print(error_code)
            continue

        # Populate org dictionary with org data from Meraki
        org_displays.append(org)

        # Get Device Count for each network
        org_devices = dashboard.organizations.getOrganizationDevices(org['id'], total_pages='all')
        network_device_counts = {}
        for item in org_devices:
            network_id = item["networkId"]

            # Increment count or start the count of devices per network at 1
            if item["networkId"] in network_device_counts:
                network_device_counts[network_id] += 1
            else:
                network_device_counts[network_id] = 1

        # Populate network dictionary with data from Meraki
        org_networks = []
        for network in networks:
            # Network device count
            if network['id'] in network_device_counts:
                device_count = network_device_counts[network['id']]
            else:
                device_count = 0

            # Network Type:
            if len(network['productTypes']) > 1:
                network_type = 'Combined'  # multiple product types present
            else:
                network_type = network['productTypes'][0].capitalize()

            # Network fields displayed on landing page table
            network_display = {'id': network['id'], 'name': network['name'], 'tags': ', '.join(network['tags']),
                               'productTypes': network_type, 'device_count': device_count}

            org_networks.append(network_display)

        network_displays.append(org_networks)

    # Render page
    return render_template('index.html', hiddenLinks=False, dropdown_content=DROPDOWN_CONTENT,
                           selected_elements=selected_elements, timeAndLocation=getSystemTimeAndLocation(),
                           organizations=org_displays, networks=network_displays, errorcode=error_code)


@app.route('/devices', methods=['GET', 'POST'])
def devices():
    """
    Devices Page, displays information about network devices (model, online status, etc.)
    :return:  Renders devices.html
    """
    # Gather selected network and org from URL params
    selected_organization = request.args.get('org')
    selected_network = request.args.get('net')

    logger.info('Devices Page Request')
    logger.info("Selected Organization: %s", selected_organization)
    logger.info("Selected Network: %s", selected_network)

    selected_elements = {
        'organization': selected_organization,
        'network_id': selected_network
    }

    # Sanity check, we should never be in sub-pages without org and network selected
    if selected_organization is None or selected_network is None:
        return redirect(url_for('index'))

    # Get device list for network
    devices = dashboard.networks.getNetworkDevices(selected_elements['network_id'])
    logger.info(f"Devices API Response: {devices}")

    # Get Device network statuses, set status field in devices list
    statuses = dashboard.organizations.getOrganizationDevicesStatuses(selected_organization, total_pages='all',
                                                                      networkIds=[selected_network])
    device_status = {}
    for status in statuses:
        device_status[status['name']] = status['status']

    for device in devices:
        device['status'] = device_status[device['name']]

    return render_template('devices.html', hiddenLinks=False, devices=devices,
                           selected_elements=selected_elements, dropdown_content=DROPDOWN_CONTENT,
                           timeAndLocation=getSystemTimeAndLocation(), error=True, errormessage="",
                           errorcode=200)


@app.route('/claim', methods=['GET', 'POST'])
def claim():
    """
    Claim devices into a network, select from unclaimed devices in the inventory.
    :return: renders claim.html
    """
    try:
        # Gather selected network and org from URL params
        selected_organization = request.args.get('org')
        selected_network = request.args.get('net')

        logger.info('Claim Page Request')
        logger.info("Selected Organization: %s", selected_organization)
        logger.info("Selected Network: %s", selected_network)

        selected_elements = {
            'organization': selected_organization,
            'network_id': selected_network
        }

        # Sanity check, we should never be in sub-pages without org and network selected
        if selected_organization is None or selected_network is None:
            return redirect(url_for('index'))

        # If success is present (during redirect after successfully updating SSID), extract URL praram
        if request.args.get('success'):
            success = request.args.get('success')
        else:
            success = False

        # Grab all Unused devices (not claimed) from Org inventory
        devices = []
        if selected_organization:
            devices = dashboard.organizations.getOrganizationInventoryDevices(selected_organization, total_pages='all',
                                                                              usedState='unused')
            logger.info(f"Found {len(devices)} Devices!")

        # Handle the form submission
        if request.method == 'POST':
            # Retrieve form data for the selected devices and action
            selected_devices = request.form.getlist('selectedDevices')

            # Parse the JSON-encoded string into a Python list
            if selected_devices and len(selected_devices) > 0:
                selected_devices = json.loads(selected_devices[0])
                action = request.form.get('action')

                logger.info(f"POST data received from client: {request.form.to_dict()}")

                # Claim devices into network
                if action == 'claim':
                    response = dashboard.networks.claimNetworkDevices(selected_network, selected_devices)
                    logger.info(f"Claim API Response: {response}")

                    return redirect(url_for('claim', org=selected_organization, net=selected_network, success=True))

        return render_template('claim.html', hiddenLinks=False,
                               selected_elements=selected_elements, devices=devices, dropdown_content=DROPDOWN_CONTENT,
                               timeAndLocation=getSystemTimeAndLocation(), error=False, success=success)

    except Exception as e:
        logger.error(f"Exception raised: {str(e)}")
        return render_template('claim.html', hiddenLinks=False, dropdown_content=DROPDOWN_CONTENT,
                               selected_elements=selected_elements, devices=devices, error=True, success=False,
                               errormessage="Error: {}".format(e), timeAndLocation=getSystemTimeAndLocation())


@app.route('/updateSSID', methods=['GET', 'POST'])
def ssid():
    """
    Update a SSID in a wireless network, change Authentication methods, name, tags, etc. Display current list of network
    SSIDs
    :return: render ssidUpdate.html
    """
    try:
        # Get the selected organization and network from the frontend form (or args if redirect)
        if request.args.get('org') and request.args.get('net'):
            selected_organization = request.args.get('org')
            selected_network = request.args.get('net')
        else:
            selected_organization = request.form.get('org')
            selected_network = request.form.get('net')

        logger.info('SSID Page Request')
        logger.info("Selected Organization: %s", selected_organization)
        logger.info("Selected Network: %s", selected_network)

        selected_elements = {
            'organization': selected_organization,
            'network_id': selected_network
        }

        # Sanity check, we should never be in sub-pages without org and network selected
        if selected_organization is None or selected_network is None:
            return redirect(url_for('index'))

        # If success is present (during redirect after successfully updating SSID), extract URL praram
        if request.args.get('success'):
            success = request.args.get('success')
        else:
            success = False

        # Grab SSIDs for the selected network, extract all AP tags from APs in network (VLAN Tagging)
        ssids = []
        ap_tags = []
        if selected_network:
            # Get all existing SSIDs
            ssids = dashboard.wireless.getNetworkWirelessSsids(selected_network)
            logger.info(f"Found {len(ssids)} SSIDs!")

            # Grab all Access Points Tags (SSID Availability)
            devices_in_network = dashboard.networks.getNetworkDevices(selected_network)
            for device in devices_in_network:
                if device['model'].startswith('MR'):
                    ap_tags.extend(tag for tag in device['tags'] if tag not in ap_tags)

            logger.info("Found the Ap Tags:%s", pp.pformat(ap_tags))

        if request.method == 'POST':
            # Retrieve form data for the selected devices and action
            selected_ssids = request.form.getlist('selectedSSIDs')

            logger.info(f"POST data received from client: {request.form.to_dict()}")

            # Parse the JSON-encoded string into a Python list
            if selected_ssids and len(selected_ssids) > 0:
                selected_ssids = json.loads(selected_ssids[0])

                # Dictionary of variable params for API call
                kwargs = {}

                # Retrieve Values from Form
                enabled = request.form.get('ssid_state')
                kwargs['enabled'] = True if enabled == 'enabled' else False

                name = request.form.get('ssid_name')
                if name != '' and name:
                    kwargs['name'] = name

                # Auth related fields
                auth_mode = request.form.get('auth')
                if auth_mode != '-- Existing --':
                    kwargs['authMode'] = auth_mode

                    # PSK Related Fields
                    if kwargs['authMode'] == 'psk':
                        kwargs['psk'] = request.form.get('password')
                        kwargs['encryptionMode'] = request.form.get('encryption')
                    # Radius Related Fields
                    elif kwargs['authMode'] == '8021x-radius':
                        area = int(request.form.get('radius-selection'))

                        # Find primary and secondary server based on area selection
                        radius_selection = {}
                        for radius_pair in RADIUS_SERVERS:
                            if radius_pair['area'] == area:
                                radius_selection = radius_pair
                                break

                        kwargs['radiusServers'] = [radius_selection['primary_server'],
                                                   radius_selection['secondary_server']]

                # SSID Availability Field
                available_on_all_aps = request.form.get('availability')
                if available_on_all_aps != '-- Existing --':
                    kwargs['availableOnAllAps'] = True if available_on_all_aps == 'all' else False

                    # If not available on all APs, get a list of tags it is available on
                    if not kwargs['availableOnAllAps']:
                        availability_tags = request.form.getlist('availability_tags')

                        # If no tags provided, then assume all
                        if len(availability_tags) == 0:
                            kwargs['availableOnAllAps'] = True
                        else:
                            kwargs['availabilityTags'] = availability_tags

                # VLAN Tagging Fields
                client_ip_vlan_mode = request.form.get('client-ip-vlan')
                if client_ip_vlan_mode != '-- Existing --':
                    kwargs['ipAssignmentMode'] = client_ip_vlan_mode
                    kwargs['useVlanTagging'] = False

                    # Ensure we are in bridge mode
                    if kwargs['ipAssignmentMode'] == 'Bridge mode':
                        kwargs['useVlanTagging'] = True

                        # Get list of VLANs and IDs (parse into Meraki format)
                        vlan_tags = request.form.getlist('vlan_tags')

                        if len(vlan_tags) > 0:
                            grouped_data = {}

                            # regex match tag name and vlan id
                            pattern = re.compile(r'(.+) \((\d+)\)')
                            for tag in vlan_tags:
                                match = pattern.match(tag)
                                if match:
                                    # split tag name and vlan id
                                    tag, vlan_id = match.groups()
                                    vlan_id = int(vlan_id)

                                    # Add VLAN ID and Tag mapping to our dictionary (either append to existing list
                                    # or create a new one)
                                    if vlan_id in grouped_data:
                                        grouped_data[vlan_id]['tags'].append(tag)
                                    else:
                                        grouped_data[vlan_id] = {'tags': [tag], 'vlanId': vlan_id}

                            # Convert the dictionary to a list (required by API)
                            kwargs[
                                "defaultVlanId"] = config.DEFAULT_VLAN  # this is needed to control how traffic is tagged on all other AP's that don't have an explicit defined mapping
                            kwargs['apTagsAndVlanIds'] = [{'tags': data['tags'], 'vlanId': data['vlanId']} for data in
                                                          grouped_data.values()]

                # Update the SSID with the given details
                for ssid in selected_ssids:
                    ssid_name_components = ssid.split(',')

                    # Extract SSID Unique Number
                    match = re.search(r'(\d+)', ssid_name_components[1])
                    ssid_number = match.group(1)

                    # Response uses kwargs dictionary, provides whatever parameters present (absence of which results
                    # in existing values kept - API field dependant!)
                    response = dashboard.wireless.updateNetworkWirelessSsid(selected_network, ssid_number, **kwargs)
                    logger.info(f"Update SSID API Response: {response}")

                return redirect(url_for('ssid', org=selected_organization, net=selected_network, success=True))

        return render_template('ssidUpdate.html', hiddenLinks=False,
                               selected_elements=selected_elements, dropdown_content=DROPDOWN_CONTENT, ssids=ssids,
                               ap_tags=ap_tags, radius_servers=RADIUS_SERVERS, default_vlan=config.DEFAULT_VLAN,
                               timeAndLocation=getSystemTimeAndLocation(), error=False, success=success)
    except Exception as e:
        logger.error(f"Exception raised: {str(e)}")
        return render_template('ssidUpdate.html', hiddenLinks=False,
                               selected_elements=selected_elements, dropdown_content=DROPDOWN_CONTENT, ssids=ssids,
                               ap_tags=ap_tags, radius_servers=RADIUS_SERVERS, default_vlan=config.DEFAULT_VLAN,
                               timeAndLocation=getSystemTimeAndLocation(), error=True,
                               errormessage="Error: {}".format(e), success=False)


@app.route('/accessPoint', methods=['GET', 'POST'])
def access_point():
    """
    Update an AP in a wireless network, change name, tags, rf_profile, etc. Display current list of APs in network
    :return: render accessPoint.html
    """
    try:
        # Get the selected organization and network from the frontend form (or args if redirect)
        if request.args.get('org') and request.args.get('net'):
            selected_organization = request.args.get('org')
            selected_network = request.args.get('net')
        else:
            selected_organization = request.form.get('org')
            selected_network = request.form.get('net')

        logger.info('Access Point Page Request')
        logger.info("Selected Organization: %s", selected_organization)
        logger.info("Selected Network: %s", selected_network)

        selected_elements = {
            'organization': selected_organization,
            'network_id': selected_network
        }

        # Sanity check, we should never be in sub-pages without org and network selected
        if selected_organization is None or selected_network is None:
            return redirect(url_for('index'))

        # If success is present (during redirect after successfully updating SSID), extract URL param
        if request.args.get('success'):
            success = request.args.get('success')
        else:
            success = False

        access_points = []
        ap_tags = []
        rf_profiles = {}
        rf_profile_names = []

        if selected_network:
            # Grab all Access Points from the selected network.
            devices_in_network = dashboard.networks.getNetworkDevices(selected_network)

            # Get Device network statuses, set status field in devices list
            statuses = dashboard.organizations.getOrganizationDevicesStatuses(selected_organization, total_pages='all',
                                                                              networkIds=[selected_network])
            device_status = {}
            for status in statuses:
                device_status[status['name']] = status['status']

            for device in devices_in_network:
                if device['model'].startswith('MR'):
                    access_points.append(device)

                    # Note AP Tags (for list of existing tags on front end form)
                    ap_tags.extend(tag for tag in device['tags'] if tag not in ap_tags)
                    # Set status field per each device
                    device['status'] = device_status[status['name']]

            logger.info(f"Found {len(access_points)} Access Points!")

            # Get RF Profiles for Network, build profile dictionary
            response = dashboard.wireless.getNetworkWirelessRfProfiles(selected_network)
            for profile in response:
                if profile['name'] != 'Basic Indoor Profile' and profile['name'] != 'Basic Outdoor Profile':
                    rf_profiles[profile['name']] = profile['id']
                    rf_profile_names.append(profile['name'])
                else:
                    rf_profiles[profile['name']] = None

            # Get Current Device RF Profiles, append field to access_point dictionaries
            for access_point in access_points:
                response = dashboard.wireless.getDeviceWirelessRadioSettings(access_point['serial'])

                if response['rfProfileId']:
                    # Non-standard RF Profile
                    rf_profile_name = list(rf_profiles.keys())[
                        list(rf_profiles.values()).index(response['rfProfileId'])]
                    access_point['rf_profile_name'] = rf_profile_name
                else:
                    # Default indoor or outdoor (use list) - determine based on model
                    model = access_point['model']
                    if model in indoor_aps:
                        access_point['rf_profile_name'] = 'Basic Indoor Profile'
                    else:
                        access_point['rf_profile_name'] = 'Basic Outdoor Profile'

        # Handle the form submission when user selects specific devices and updates them.
        if request.method == 'POST':
            # Retrieve list of selected devices from the frontend form.
            selected_devices = request.form.getlist('selectedDevices')

            logger.info(f"POST data received from client: {request.form.to_dict()}")

            if selected_devices and len(selected_devices) > 0:
                selected_devices = json.loads(selected_devices[0])

                # Dictionary of variable params for API call
                kwargs = {}

                # Special default handling kwargs used further down (api wipes values if none provided)
                device_name = request.form.get('device_name')
                rf_profile_name = request.form.get('rf_profile')
                device_tags = request.form.getlist('ap_tags')

                # Directly proceed to update
                for serial in selected_devices:
                    try:
                        # Get Device Baseline (use these fields as defaults if no new data provided)
                        current_device = None
                        for access_point in access_points:
                            if access_point['serial'] == serial:
                                current_device = access_point

                        # Set Default Values if Necessary
                        kwargs['name'] = device_name if device_name != '' and device_name else current_device['name']
                        kwargs['tags'] = device_tags if len(device_tags) > 0 else current_device['tags']

                        # Update Device Params (Name, Tag, etc.)
                        device = dashboard.devices.updateDevice(serial=serial, **kwargs)
                        logger.info(f"Update Device API Response: {device}")

                        # RF Profile name
                        rf_profile_name = rf_profile_name if rf_profile_name != '-- Existing --' else None

                        # Update Device RF Profile
                        if rf_profile_name == 'Basic Profile (Indoor/Outdoor)':
                            # Special Case (change to appropriate basic profile based on MR model)
                            if device['model'] in indoor_aps:
                                rf_profile_name = 'Basic Indoor Profile'
                            else:
                                rf_profile_name = 'Basic Outdoor Profile'

                        # Update RF Profile if specified
                        if rf_profile_name:
                            rf_profile_id = rf_profiles[rf_profile_name]
                            response = dashboard.wireless.updateDeviceWirelessRadioSettings(serial=serial,
                                                                                            rfProfileId=rf_profile_id)
                            logger.info(f"Update RF Profile API Response: {response}")

                    except Exception as e:
                        logging.error(f"Failed to update device with serial {serial}. Error: {str(e)}")

                return redirect(
                    url_for('access_point', org=selected_organization, net=selected_network, success=True))

        # Render the AccessPoint.html template with the required data.
        return render_template('accessPoint.html', hiddenLinks=False,
                               selected_elements=selected_elements, devices=access_points, ap_tags=ap_tags,
                               rf_profile_names=sorted(rf_profile_names), dropdown_content=DROPDOWN_CONTENT,
                               timeAndLocation=getSystemTimeAndLocation(), error=False, success=success)
    except Exception as e:
        # Render the AccessPoint.html template with the required data (on error, error written to file, no need to
        # freeze up webpage)
        logger.error(f"Exception raised: {str(e)}")
        return render_template('accessPoint.html', hiddenLinks=False,
                               selected_elements=selected_elements, devices=access_points, ap_tags=ap_tags,
                               rf_profile_names=sorted(rf_profile_names), dropdown_content=DROPDOWN_CONTENT,
                               timeAndLocation=getSystemTimeAndLocation(), error=True,
                               errormessage="Error: {}".format(e), success=False)


if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=False)
