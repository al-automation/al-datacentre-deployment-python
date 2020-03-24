# Datacenter Alert Logic Deployment using Python
This is a python script that will allow you to create a Datacenter deployment in the Alert Logic Console.

## Usage
#### These properties are required to ensure that the script can create the deployment successfully. 

Authentication (Note, that if you enter both username/password and access keys, access keys will be used by default):
- alert_logic_username = '' // Alert Logic Username
- alert_logic_password = '' // Alert Logic Password

- alert_logic_access_apikey = '' // Alert Logic Access Key
- alert_logic_secret_apikey = '' // Alert Logic Secret Key

Configuration:
- alert_logic_cid = "" // Alert Logic Customer ID
- alert_logic_deployment_name = "" // The name you would like the Alert Logic Deployment created with
- entitlement = "" // Alert Logic Entitlement Level (Essentials or Professional)

### Examples for how to add Networks & External assets
#### Inside the python list 'network = []', you will need to create a list for each of the specific Networks you would like to add to the deployment, along with the CIDR ranges of that network(s). These networks need to have a particular format: 
- All networks need to be added as a list, inside the existing networks list
- The first value in each list must be the name of the network
- The CIDR ranges for that network must follow on from the network name, in a list format. 

#### Example: 

Let's say we have 2 networks that we need to add to this deployment: 
- Network with name "test-network-1" with 3 CIDR range:  10.10.10.0/24, 10.10.11.0/24, 10.10.12.0/24
- Network with name "test-network-2" with 2 CIDR range:  10.10.20.0/24, 10.10.21.0/24
- Network with name "test-network-3" with 1 CIDR range:  10.10.30.0/24

The networks inside the network.csv file will look like this: 

test-network,10.10.10.0/24,10.10.11.0/24,10.10.12.0/24
test-network-2,10.10.20.0/24,10.10.21.0/24
test-network-3,10.10.30.0/24

#### These objects are required for external assets to be scanned externally by Alert Logic's Datacentre, post deployment. 
- external_dns_names=["www.example.com","www.google.com"]
- external_ip_addresses=["8.8.8.8", "8.8.4.4"]

### How to run the script: 
python3 create_dc_deployment.py
