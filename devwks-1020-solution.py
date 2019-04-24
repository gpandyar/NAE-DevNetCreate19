#!/usr/bin/env python
import requests
import json
from variables import *

#Disable warnings
requests.packages.urllib3.disable_warnings()

def main():
    """
    Main body for DEVWKS-1020. In this, we will
        1. Create a session to the NAE instance
        2. Access all fabrics
        3. Fetch running fabric
        4. Fetch last 20 epochs 
        5. Fetch latest epoch
        6. Fetch event summary for the latest epoch
        7. Fetch events by
            a. category
            b. severity
        8. Find all the epochs in which an event exists

    """
    print_banner("Create a session to the NAE instance")
    # Logon to the NAE instance and print credentials
    if nae_login(NAE_IP, NAE_USER, NAE_PASS):
        header = NAE_HEADER
    else:
        print ("Login failed to: " + NAE_IP + " with username: " + NAE_USER + " and password: " + NAE_PASS)
    print (json.dumps(NAE_HEADER, indent=4, sort_keys=True))

    print_banner("Get all fabric ids")
    # Get all fabric Ids
    fabric_ids = get_fabric_ids()
    print (json.dumps(fabric_ids, indent=4, sort_keys=True))

    
    print_banner("Fetch running fabric")
    # Get running fabric
    for fabric in fabric_ids:
        if fabric['status'] == 'RUNNING':
            RUNNING_FABRIC_ID = fabric['id']
        else:
            RUNNING_FABRIC_ID = None
    print (RUNNING_FABRIC_ID)

    if not RUNNING_FABRIC_ID:
        print ("No running fabric found. Using the first fabric from the list")
        RUNNING_FABRIC_ID = fabric_ids[0]['id']

    print_banner("Fetch last 20 epochs")
    # Get latest 20 epochs
    last_20_epochs = get_epoch_ids(RUNNING_FABRIC_ID, 20)
    print (json.dumps(last_20_epochs, indent=4, sort_keys=True))

    
    print_banner("Fetch latest epoch")
    # Get latest epoch
    latest_epoch =  get_epoch_ids(RUNNING_FABRIC_ID, 1)[0]
    print ("Latest Epoch: " + latest_epoch)

    print_banner("Fetch event summary for the latest epoch")
    # Fetch smart events for the latest epoch for running fabric
    fetch_smart_event_summary(RUNNING_FABRIC_ID, latest_epoch)
    print("event summary by SEVERITY: ")
    print(json.dumps(SEVERITY, indent=4, sort_keys=True))
    print("event summary by CATEGORY: ")
    print(json.dumps(CATEGORY, indent=4, sort_keys=True))
    print("event summary by MNEMONIC: ")
    print(json.dumps(MNEMONIC, indent=4, sort_keys=True))

    print_banner("Fetch events by category & severity")
    # Fetch smart events with category_name "SYSTEM" & severity "EVENT_SEVERITY_CRITICAL"
    # from the latest epoch on running fabric
    res = fetch_smart_events(RUNNING_FABRIC_ID, latest_epoch,
     param_dict={'severity': 'EVENT_SEVERITY_CRITICAL', 
                 'category_name': 'SYSTEM'})
    event_list = []
    for event in res['value']['data']:
        event_dict = {}
        event_dict['severity'] = event['severity']['name']
        event_dict['category'] = event['category']['name']
        event_dict['sub_category'] = event['sub_category']['name']
        event_dict['smart_event_info'] = event['smart_event_info']['name']
        event_dict['id'] = event['identifier']
        event_list.append(event_dict)
    print (json.dumps(event_list, indent=4, sort_keys=True))

    print_banner("Epochs by Event Id")
    # Fetch epochs for a given event id
    epochs_by_event = get_epochs_by_event_id(fabric_id=RUNNING_FABRIC_ID, event_id=event_list[0]['id'])
    print (json.dumps(epochs_by_event, indent=4, sort_keys=True))

def print_banner(message):
    """
    Print a banner
    """
    print ("\n\n*************************************")
    print (message)
    print ("*************************************")


def nae_login(nae_ip, nae_user, nae_pass):
    """
    Logon to NAE
        :parameter:
            nae_ip (required): IP address of Cisco NAE instance to connect to
            nae_user (required): User name to log on to device specified by nae_ip
            nae_pass (required): Password for nae_user
    """
    data = dict() 
    data['username'] = nae_user
    data['password'] = nae_pass 
    data = json.dumps(data)

    header = dict()
    header["Content-Type"] = "application/json"
    header["Accept"] = "application/json"

    '''
        Executes whoami request first to get the one time password and retireves session id, which will be used to login and 
        get the actual token and session id that will be used in all subsequent REST Call.
        URL - "https://nae_ip/api/v1/whoami"
    '''
    wmi_req = requests.get(url=WMI_URL, headers=header, verify=False)
    
    if wmi_req.status_code is 200 or wmi_req.status_code is 201:
        otp = wmi_req.headers['X-NAE-LOGIN-OTP']
        sid = wmi_req.headers['Set-Cookie']
        sid = str(sid).split(';')[0]

        '''
            Taking one time password and session id as inputs, this generates a token after authenticating 
            (Username and Password sent in the body).
            URL - URL - "https://nae_ip/api/v1/login"
        '''
        header['X-NAE-LOGIN-OTP'] = otp
        header['Cookie'] = sid
        req = requests.post(url=LOGIN_URL, data=data, headers=header, verify=False)

        if req.status_code is 200 or req.status_code is 201:
            nae_token = req.headers['X-NAE-CSRF-TOKEN']
            cookie = req.headers['Set-Cookie']
            nae_session = str(cookie).split(';')[0]

            NAE_HEADER["Content-Type"] = "application/json" 
            NAE_HEADER["Accept"] = "application/json" 
            NAE_HEADER['X-NAE-CSRF-TOKEN'] = nae_token 
            NAE_HEADER['Cookie'] = nae_session
            return True
        else:
            return False

def get_fabric_ids():
    """
    Get a list of all Fabrics, along with APICs
        :return:
            fabric_ids: All fabrics, along with APIC IPs
            Type: List
    """
    fabric_ids = dict()
    fabric_ids = []

    '''
        Build URL and send the request. URL - "https://{nae_ip}/api/v1/assured-networks/aci-fabric"
    '''
    req = requests.get(url=FABRIC_URL, headers=NAE_HEADER, verify=False)
    if req.status_code is 200:
        resp = json.dumps(req.json())
        res = json.loads(resp)
        data_no = len(res['value']['data'])
        # exit(1)
        '''
            Write all fabric UUIDs to an array and return the array
        '''
        for f in range(0, data_no):
            fab = dict()
            print(json.dumps(res['value']['data'][f], indent=4))
            fab['id'] = res['value']['data'][f]['uuid']
            fab['status'] = res['value']['data'][f]['status']
            if fab['status'] == 'RUNNING':
                fab['apic_hosts'] = res['value']['data'][f]['apic_hostnames']
            fabric_ids.append(fab)
    print ("Fabric Ids: ")
    print (fabric_ids)
    return fabric_ids

def get_epoch_ids(fabric_id, count):
    
    '''
        Build URL and send the request. URL - "https://cnae_ip/api/v1/assured-networks/<fabric_id>/epochs/$latest"
    '''
    epochs = []
    epoch_url = NAE_BASE_URL+"assured-networks/" + str(fabric_id) + "/epochs?$size=" + str(count) + "&$page=0"

    req = requests.get(url=epoch_url, headers=NAE_HEADER, verify=False)

    if req.status_code is 200:
        resp = json.dumps(req.json())
        res = json.loads(resp)
        for epoch in res['value']['data']:
            epochs.append(epoch['epoch_id'])
    return epochs

def fetch_smart_events(fabric_id, epoch_id, event_id=None, param_dict=None):
    # HEADER WITH ALL THE AUTH DETAILS
    print ("***********************************************************")
    print ("Please wait while we fetch smart events for fabric: " + str(fabric_id) + " epoch: " + str(epoch_id))
    print ("***********************************************************")
    
    '''
        Build URL and send the request. 
        URL - "https://cnae_ip/api/v1/assured-networks/<fabric_id>/smart-events?$epoch_id=<epoch_id>
    '''
    smart_events = NAE_BASE_URL+"assured-networks/"+fabric_id+"/smart-events?$epoch_id="+epoch_id

    if event_id:
        smart_events = smart_events + "/" + event_id
    elif param_dict:
        for param in param_dict.keys():
            smart_events = smart_events + "&" + param + "=" + param_dict[param]

    print smart_events
    req1 = requests.get(url=smart_events, headers=NAE_HEADER, verify=False)
    if req1.status_code is 200:
        resp1 = json.dumps(req1.json())
        res1 = json.loads(resp1)
        return res1
    else:
        return None

def fetch_smart_event_summary(fabric_id, epoch_id, param_dict={}):
    # HEADER WITH ALL THE AUTH DETAILS
    print ("***********************************************************")
    print ("Please wait while we fetch smart events for fabric: " + str(fabric_id) + " epoch: " + str(epoch_id))
    print ("***********************************************************")
    
    '''
        Build URL and send the request. 
        URL - "https://cnae_ip/api/v1/assured-networks/<fabric_id>/smart-events?$epoch_id=<epoch_id>
    '''
    smart_events = NAE_BASE_URL+"assured-networks/"+fabric_id+"/smart-events?$epoch_id="+epoch_id

    for param in param_dict.keys():
        smart_events = smart_events + "&" + param + "=" + param_dict[param]

    print smart_events
    req1 = requests.get(url=smart_events, headers=NAE_HEADER, verify=False)
    if req1.status_code is 200:
        resp1 = json.dumps(req1.json())
        res1 = json.loads(resp1)
        page_count = res1['value']['data_summary']['total_page_count']
        for j in range(0, page_count):
            smart_event_url = smart_events+'&$page='+str(j)
            req = requests.get(url=smart_event_url, headers=NAE_HEADER, verify=False)
            if req.status_code is 200:
                resp = json.dumps(req.json())
                res = json.loads(resp)            
                proc_smart_events(res)
        return True 
    else:
        return None

def proc_smart_events(res):
    for i in range(0, len(res['value']['data'])):
        cat = res['value']['data'][i]['category']['name']
        sev = res['value']['data'][i]['severity']['name']
        mnmnic = res['value']['data'][i]['smart_event_info']['name']
        sub_category = res['value']['data'][i]['sub_category']['name']
        proc_sev(sev)
        proc_cat(cat)
        proc_mne(mnmnic)

# PROCESS SEVERITY
def proc_sev(sev):
    SEVERITY[sev] = SEVERITY.get(sev, 0) + 1
 
# PROCESS CATEGORY
def proc_cat(cat):
    CATEGORY[cat] = CATEGORY.get(cat, 0) + 1

# PROCESS MNEMONIC
def proc_mne(mnmnic):
    MNEMONIC[mnmnic] = MNEMONIC.get(mnmnic, 0) + 1


def get_epochs_by_event_id(fabric_id, event_id):
    epoch_url = NAE_BASE_URL + "assured-networks/" + fabric_id + "/epochs?$event_id=" + event_id
    req = requests.get(url=epoch_url, headers=NAE_HEADER, verify=False)

    epochs=[]
    if req.status_code is 200:
        resp = json.dumps(req.json())
        res = json.loads(resp)
        for epoch in res['value']['data']:
            epochs.append(epoch['epoch_id'])
    return epochs

if __name__ == '__main__':
    main()