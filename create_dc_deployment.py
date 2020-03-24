#!/usr/bin/python3 -u

#Wriiten for python 3.7.3

#Required Libraries
import json
import csv
import os
import requests
import time
from datetime import datetime

#Read in configuration file
from create_dc_deployment_properties import *
#from create_dc_deployment_properties_test import *

#Setting true/false variables to avoid conflict later
true=True
false=False

#Set global URL's
global_url= 'https://api.global.alertlogic.com/'

#Header just to make the script look prettier
print('''
====================================================================================================

              :ydho`                 Title:     Create_Deployment.sh
            +ddddd:                 Author:     Alert Logic Deployment Services
           .ddddh+             Description:     A tool for creating deployments
           yddy/``                              into the Alert Logic UI for
          +dh:   +/                             your chosen Customer ID
         +dy` ''',end='')
print('``',end='')
print('''  sy-
       `odh.''',end='')
print('-/+++-', end='')
print('''.dd+`
      .yddo ''',end='')
print(':++++/',end='')
print(''' sddy-            Usage:      python3 Create_Deployment.py
     /hddd/  ''',end='')
print('.::-',end='')
print('''  sdddh/
    /ddddd-        oddddd.           Note:      Ensure that all required fields in the configuration
    +dddds         .hdddh`                      file have been input. For any assistance, please
     .::.            -:-`                       contact Alert Logic Deployment Services

====================================================================================================
''')

#Checks to ensure that the configuration file has all required fields before even starting the script

if alert_logic_cid == '':
	print ('\nThe Alert Logic Customer ID has not been stored in the configuration file.\n')
	exit()

if alert_logic_deployment_name == '':
        print ('\nThe name for the deployment has not been stored in the configuration file.\n')
        exit()

entitlement=entitlement.capitalize()

if entitlement == '':
        print ('\nThe protection level has not been set in the configuration file.\n')
        exit()
elif entitlement not in ['Professional','Essentials']:
	print('\nThe protection level has been set incorrectly in the configuration file. Please specify either "Essentials" or "Professional".\n')
	exit()

#Function to get AIMS Token once we have creds
def get_token_userpass ():
	url = f'{global_url}aims/v1/authenticate'
	global auth_token
	#Use credentials
	aims_user = alert_logic_username
	aims_pass = alert_logic_password

	if "alertlogic.com" in aims_user :
		print ('\nError: Alert Logic User Detected. Cannot authenticate since MFA is mandatory. Use API Keys.\n')
		exit()

	print('\nValidating stored credentials...', end = '')

	#POST request to the URL using credentials. Load the response into auth_info then parse out the token
	token_response = requests.post(url, auth=(aims_user, aims_pass))

	if token_response.status_code != 200:
		print('Error: Could not authenticate. Got the following response: ',end='')
		print(token_response)
		print()
		exit()

	auth_info = json.loads(token_response.text)
	auth_token = auth_info['authentication']['token']

#Same as previous, but uses stored API Keys if they are detected
def get_token_apikey ():
	url = f'{global_url}aims/v1/authenticate'
	global auth_token
	print('Detected stored API Keys. Validating...', end = '')
	#POST request to the URL using keys. Load the response into auth_info then parse out the token
	token_response = requests.post(url, auth=(alert_logic_access_apikey, alert_logic_secret_apikey))

	if token_response.status_code != 200:
		print('Error: Could not authenticate. Got the following response: ',end='')
		print(token_response)
		print()
		exit()

	auth_info = json.loads(token_response.text)
	auth_token = auth_info['authentication']['token']

#Function to validate the AIMS token was successfully generated, and that it has not expired
def validate_token ():
	url = f'{global_url}aims/v1/token_info'
	headers = {'x-aims-auth-token': f'{auth_token}'}
	global validate_info
	validate_response = requests.get(url, headers=headers)
	validate_info = json.loads(validate_response.text)

	#get current unix timestamp,make global for later
	global current_time
	current_time = int(time.time())
	#get token expiration timestamp
	token_expiration = validate_info['token_expiration']
	num_seconds_before_expired=(token_expiration - current_time)

	if num_seconds_before_expired < 0 :
		print(' Errror: Could not generate / validate AIMS Token. Please check credentials and try again\n')
		exit()
	else :
		print(' AIMS token generated and validated.\n')
		time.sleep(1)

if alert_logic_access_apikey != '' and alert_logic_secret_apikey != '':
	get_token_apikey()
	validate_token()
elif alert_logic_username != '' and alert_logic_password != '':
	get_token_userpass()
	validate_token()
else:
	print ('\nError: No credentials stored in the configuration file, to allow authentication against the API.\n')
	exit()
#Authentication complete

headers = {"x-aims-auth-token": f"{auth_token}"} #Set header for all future API calls

#Get base endpoint for customer ID
endpoint_url = f'{global_url}endpoints/v1/{alert_logic_cid}/residency/default/services/assets/endpoint/api'
endpoint_response = requests.get(endpoint_url, headers=headers)

#In case we don't get a 200 response getting the endpoint
if endpoint_response.status_code != 200:
	print('Error: Could not determine API endpoint for the Customer ID stored. Got response code: ' + str(endpoint_response.status_code))
	print()
	exit()

endpoint_info = json.loads(endpoint_response.text)
base_url = endpoint_info['assets']
base_url = 'https://' + base_url

#Get CID that the token exists in (CID the authenticated user was in). Then check if that CID is authorised to view
users_CID = validate_info['user']['account_id']

#Print out authenticated user information
print('Authenticated Users Info:\n')
user_name = validate_info['user']['name']
user_email = validate_info['user']['email']
user_role = validate_info['roles'][0]['name']
user_lastlogin_unix = validate_info['user']['user_credential']['last_login']
user_lastlogin_hr = datetime.utcfromtimestamp(user_lastlogin_unix ).strftime('%d/%m/%Y %H:%M:%S %Z')
print('    Name: ' + user_name)
print('    Email: ' + user_email)
print('    User Role: ' + user_role)
print('    CID: ' + users_CID)
#print('    Last authentication: ' + user_lastlogin_hr) #Don't think this is needed, last time user logged into the UI
print()


#If the CID the user has authenticated from, is not equal to the target CID
if alert_logic_cid != users_CID:
	#This is checking whether there is a managed relationship (ensuring a parent-child relationship) between the 2 CID's.
	managed_CID_check_url = f'{global_url}aims/v1/{users_CID}/accounts/managed/{alert_logic_cid}'
	managed_CID_check_response = requests.get(managed_CID_check_url, headers=headers)
	managed_CID_check_statuscode = managed_CID_check_response.status_code

	#1 - Make sure the CID's have a managed relationship (Status Code 204 is a success response)
	if managed_CID_check_statuscode != 204:
		print(' Error: Authenticated user does not have authorisation to perform actions in CID ' + alert_logic_cid + ' Please try another user.\n')
		exit()

	#2 - If yes to step 1, make sure authenticated user has permissions to create stuff in target CID
	if user_role == 'Read Only' or user_role == 'Support/Care' or user_role == 'Power User' :
		print ('Error: Authenticated user does not have the required permission to create in CID ' + alert_logic_cid)
		print ('\n    - User must be Administrator or Owner\n')
		exit()

#If the CID the user has authenticated from, is equal to the target CID
elif alert_logic_cid == users_CID:
	# Make sure the autenticated user has permission to create in target CID
	if user_role == 'Read Only' or user_role == 'Support/Care' :
		print ('Error: Authenticated user does not have the required permission to create in CID ' + alert_logic_cid)
		print ('\n    - User must be Administrator, Owner or Power user\n')
		exit()

#Get some account information from the CID
print('Target CID Info:\n')
account_info_url = f'{global_url}aims/v1/{alert_logic_cid}/account'
account_info_response = requests.get(account_info_url, headers=headers)
account_info = json.loads(account_info_response.text)
account_name = account_info['name']
account_CID = alert_logic_cid
account_defaultloc = account_info['default_location']
print('    Account Name: ' + account_name)
print('    Accound CID: ' + account_CID)
print('    Default Location: ' + account_defaultloc)
print('    Base URL: ' + base_url)
print()

#Get the policy ID's for the protection levels.
policies_info_url = f'{base_url}/policies/v1/{alert_logic_cid}/policies'
policies_info_response = requests.get(policies_info_url, headers=headers)
policies_info = json.loads(policies_info_response.text)
#The following code pulls in the entitlement set in the configuration file and returns the entitlement ID
entitlement=entitlement.capitalize()
policy_id = [x for x in policies_info if x['name'] == entitlement]
entitlement_id=policy_id[0]['id']

#Function to create the deployment, adding in all
def create_deployment ():

	deployment_payload ={
			"mode": "manual",
			"discover": true,
			"enabled": true,
			"scan": true,
			"name": alert_logic_deployment_name,
			"cloud_defender": {
				"enabled": false,
				"location_id": account_defaultloc
				},
			"platform": {
				"type": "datacenter"
			},
			"scope": {
				"include": [],
			}
		}

	create_deployment_payload=json.dumps(deployment_payload)
	create_deployment_payload_final=create_deployment_payload.replace("\\", "")
	create_deployment_payload_final=create_deployment_payload_final.replace('""', '')

	create_deployment_url = f'{base_url}/deployments/v1/{alert_logic_cid}/deployments'
	create_deployment_response = requests.post(create_deployment_url, create_deployment_payload_final, headers=headers)
	if create_deployment_response.status_code != 201:
		print('    Error: Deployment creation failed. Got the following response: '+ str(create_deployment_response.status_code))
		print()
		exit()
	else :
		print('    Deployment successfully created. You should now see this deployment in the Alert Logic Console.')
		print()

	create_deployment_info = json.loads(create_deployment_response.text)
	global deployment_id
	deployment_id=create_deployment_info['id']

def create_networks ():
	global network_keys
	global protected_networks
	global list_networks
	network_keys = []
	protected_networks = []
	list_networks = [] 

	if not network_csv_file:
		print("    No networks detected in a csv file. Please provide the file path to the list of networks in a .csv on the properties file.\n")
		protected_networks.append("\t\t\t\tNo networks defined")
	else: 
		#Read from networks csv file
		with open(network_csv_file, newline='') as csv_file:
			reader = csv.reader(csv_file)
			networks = list(reader)

		for x in networks: 
			#Pull out network name as the first value in list
			network_name=x[0]
			cidr_list = []
			
			#For every value other than the first, append to new list
			for cidr in x[1:]: 
				cidr_list.append(cidr)
		
			#Format the cidr list ready for the POST payload
			json_cidr_list=str(cidr_list)[1:-1]
			
			#Network creation payload
			network_payload = {
					"network_name": network_name,
					"cidr_ranges": [(json_cidr_list)],
					"span_port_enabled": true
				}
	
			#Convert the payload (including the cidr list) into json
			create_network_payload=json.dumps(network_payload)
			#Inside the scope, replace the [" "] so it's just [ ] 
			create_network_payload=create_network_payload.replace('["','[')
			create_network_payload=create_network_payload.replace('"]',']')
			#Change the objects inside the cidr list to be surrounded by double quotes instead of single
			create_network_payload=create_network_payload.replace("'",'"')
			print(create_network_payload)
			#Create networks and store the network keys into a new list, network_keys (so that we can add to scope later)
			create_network_url = f'{base_url}/assets_manager/v1/{alert_logic_cid}/deployments/{deployment_id}/networks'
			create_network_response = requests.post(create_network_url, create_network_payload, headers=headers)
			print(create_network_url)

			if create_network_response.status_code !=200: 
				print('    Error: Network with name '+network_name+ ' creation failed. Got the following response: '+ str(create_network_response.status_code))
			else: 
				print('    Network with name '+network_name+ ' created successfully, with CIDR ranges ' + json_cidr_list)
				protected_networks.append("\t\t\t\tNetwork: "+network_name+"\tCIDR's: "+str(cidr_list)[1:-1].replace("'", "")+"\n")
			
			create_network_info = json.loads(create_network_response.text)
			print(create_network_info)
			global network_key
			global claim_key
			network_key=create_network_info['key']
			network_keys.append(network_key)
			claim_key=create_network_info['claim_key']
			list_networks.append("    Network Name: " +network_name+"\t\tUnique Key: "+claim_key+"\n")
			
			#Find the network UUID for creating subnets later
			global network_id
			#Giving the network time create, was failing going straight into this
			time.sleep(1)
			#Query assets_query for full network info
			network_id_url = f'{base_url}/assets_query/v1/{alert_logic_cid}/deployments/{deployment_id}/assets?asset_types=v:vpc&v.key={network_key}'
			network_uuid_response = requests.get(network_id_url, headers=headers)
			#Pull network_uuid value out
			network_uuid_info = json.loads(network_uuid_response.text)
			network_uuid_info=network_uuid_info['assets'][0]
			network_id=network_uuid_info[0]['network_uuid']

			#Subnet creation for each network
			for each_cidr in cidr_list:
				print(each_cidr)
				list_subnets = [] 
				
				#Subnet creation payload
				subnet_name = network_name+ ' (' +each_cidr+ ')'
				subnet_payload = {
						"subnet_name": subnet_name,
						"cidr_block": (each_cidr)
					}

				#Convert the payload into json
				create_subnet_payload=json.dumps(subnet_payload)
				print(create_subnet_payload)
				#Inside the scope, replace the [" "] so it's just [ ] 
				create_subnet_payload=create_subnet_payload.replace('["','[')
				create_subnet_payload=create_subnet_payload.replace('"]',']')
				#Change the objects inside the cidr list to be surrounded by double quotes instead of single
				create_subnet_payload=create_subnet_payload.replace("'",'"')
				
				#Create networks and store the network keys into a new list, network_keys (so that we can add to scope later)
				create_subnet_url = f'{base_url}/assets_manager/v1/{alert_logic_cid}/deployments/{deployment_id}/networks/{network_id}/subnets'
				print(create_subnet_url)
				create_subnet_response = requests.post(create_subnet_url, create_subnet_payload, headers=headers)
				
				if create_subnet_response.status_code !=200: 
					print('    Error: Subnet with name '+subnet_name+ ' creation failed. Got the following response: '+ str(create_subnet_response.status_code))
				else: 
					print('    Subnet with name '+subnet_name+ ' created successfully, with CIDR block ' + each_cidr)
					#protected_subnets.append("\t\t\t\tNetwork: "+network_name+"\tCIDR's: "+str(cidr_list)[1:-1].replace("'", "")+"\n")

				list_subnets.append("    Subnet Name: " +subnet_name+ "\n")
			
	print()
	
	#Print created networks and the associated claim key
	list_networks=''.join(list_networks)
	print("The networks just created, and their associated unique registration keys: ")
	print(str(list_networks))
	print("The subnets just created, and their associated unique registration keys: ")
	print(str(list_subnets))	
	#For logging purposes
	protected_networks=''.join(protected_networks)

def set_scope_protection (): 
	scope_list = []
	
	if not network_keys: 
		print("    No networks were created. Skipping.")
	else: 

		for key in network_keys: 
			scope_list.append("{\"key\":\""+key+"\",\"type\":\"vpc\",\"policy\":{\"id\":\""+entitlement_id+"\"}}")
	
		#Convert python list to string
		scope=str(scope_list)[1:-1]
	
		#Remove single quotes between each json object, dump into json then remove any extra slashes
		scope_json=scope.replace("'","")
		scope_json=json.dumps(scope_json)
		scope_json=scope_json.replace("\\", "")
	
		update_scope_payload={
			"version": 1,
			"scope": {
				"include": [(scope_json)],
				}
			}
		
		update_scope_payload=json.dumps(update_scope_payload)
		update_scope_payload=update_scope_payload.replace("\\", "")
		update_scope_payload=update_scope_payload.replace('""', "")
		update_scope_url = f'{base_url}/deployments/v1/{alert_logic_cid}/deployments/{deployment_id}'
		update_scope_response = requests.put(update_scope_url, update_scope_payload, headers=headers)
	
		if update_scope_response.status_code !=200:
			print('    Error: Protection levels not added to deployment with name "'+alert_logic_deployment_name+'". Got the following response code: '+str(update_scope_response.status_code))
		else:
			print('    Protection levels successfully added to deployment with name "'+alert_logic_deployment_name+'"')
	print()

def create_external_assets ():
	global external_assets_logging
	external_assets_logging=[]

	if not external_dns_names: 
		print('    No external DNS names to add')
	else:
		for dns in external_dns_names:

			dns_payload= {
				"operation": "declare_asset",
				"type": "external-dns-name",
				"scope": "config",
				"key": "/external-dns-name/"+dns+"",
				"properties": {
					"name": ""+dns+"",
					"dns_name": ""+dns+"",
					"state": "new"
				}
			}

			create_dns_payload=json.dumps(dns_payload)
			create_dns_url = f'{base_url}/assets_write/v1/{alert_logic_cid}/deployments/{deployment_id}/assets'
			create_dns_response = requests.put(create_dns_url, create_dns_payload, headers=headers)

			if create_dns_response.status_code != 201:
				print('    Error: DNS with name '+dns+' was unable to be added. Got the following response: ',end='')
				print(create_dns_response)
			else :
				print('    DNS with name '+dns+' added successfully.')
				external_assets_logging.append("\t\t\t\tExternal DNS: "+dns+"\n")

	if not external_ip_addresses:
                print('    No external IP addresses to add')
	else:
		for ip in external_ip_addresses:

			ip_payload= {
                                "operation": "declare_asset",
                                "type": "external-ip",
                                "scope": "config",
                                "key": "/external-ip/"+ip+"",
                                "properties": {
                                        "name": ""+ip+"",
                                        "dns_name": ""+ip+"",
                                        "state": "new"
                                }
                        }

	
			create_ip_payload=json.dumps(ip_payload)
			create_ip_url = f'{base_url}/assets_write/v1/{alert_logic_cid}/deployments/{deployment_id}/assets'
			create_ip_response = requests.put(create_ip_url, create_ip_payload, headers=headers)

			if create_ip_response.status_code != 201:
				print('    Error: IP address '+ip+' was unable to be added. Got the following response: ',end='')
				print(create_ip_response)
			else :
				print('    IP address '+ip+' added successfully.')
				external_assets_logging.append("\t\t\t\tExternal IP: "+ip+"\n")
		print()
	
	#Logging External Assets
	if not external_assets_logging:
		external_assets_logging.append("\t\t\t\tNo external assets defined")
	external_assets_logging=''.join(external_assets_logging)

#Create all necessary elements 
print("Creating Deployment...")
create_deployment()
print("Creating Networks...")
create_networks()
print("Setting Protection Level on Networks...")
set_scope_protection()
print("Creating External Assets...")
create_external_assets()
print()

#List all deployments
print('Deployments for account '+alert_logic_cid+':\n')
all_deployments_url = f'{base_url}/deployments/v1/{alert_logic_cid}/deployments'
all_deployments_response = requests.get(all_deployments_url, headers=headers)
if all_deployments_response.status_code != 200:
	print('    Could not get existing deployments. Got response code: '+all_deployments_response.status_code)
else:
	all_deployments_info = json.loads(all_deployments_response.text)
	all_deployments_list = []
	all_deployments_list.append(["Name", "Platform", "ID", "Status"])
	#Parsing deployment output and outputting to user
	for i in range(len(all_deployments_info)):
		deployment_name=all_deployments_info[i]['name']
		deployment_platform=all_deployments_info[i]['platform']['type']
		deployment_id=all_deployments_info[i]['id']
		deployment_status=all_deployments_info[i]['status']['status']
		all_deployments_list.append([deployment_name, deployment_platform, deployment_id, deployment_status])

lengths = [max(len(str(row[i])) for row in all_deployments_list) for i in range(len(all_deployments_list[0]))] 
dep_list = ' '.join('{:<%d}' % l for l in lengths)
print(dep_list.format(*all_deployments_list[0]))
print('-' * (sum(lengths) + len(lengths) - 1))
for row in all_deployments_list[1:]:
    print(dep_list.format(*row))
print()

#Logging - Write to log file
#At the moment this is writing everything manually, may create a text payload and write that instead (more configurable). 
filename = 'datacenter-'+alert_logic_cid+'.log'
date_time=(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(current_time)))
if os.path.exists(filename):
    append_write = 'a' # append if already exists
else:
    append_write = 'w' # make a new file if not

write_log = open(filename,append_write)
write_log.write(str(date_time) + ":\tDeployment Name: " + alert_logic_deployment_name + "\n" + "\t\t\tEntitlement: " +entitlement+"\n" + "\t\t\tCreated By: " +user_name+"\n" + "\t\t\tProtected Networks: \n" +str(protected_networks)+"\n" + "\t\t\tExternal Assets: \n" + external_assets_logging+"\n")
write_log.close()
