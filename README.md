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

### Examples for how to add Networks & External assets
#### Inside the file 'networks.csv', you will need to create an entry for each of the specific Networks you would like to add to the deployment, along with the CIDR ranges of that network. These networks need to have a particular format: 
- All networks need to be added as a list, inside the existing networks list
- The first value in each line must be the name of the network, comma delimited
- The second value in each line must be the entitlement level (Essentials or Professional), comma delimited
- The CIDR ranges for that network must follow on from the entitlement level, comma delimited for each CIDR range

#### Example: 

Let's say we have 2 networks that we need to add to this deployment: 
- Network with name "test-network-1" with 3 CIDR range:  10.10.10.0/24, 10.10.11.0/24, 10.10.12.0/24
- Network with name "test-network-2" with 2 CIDR range:  10.10.20.0/24, 10.10.21.0/24
- Network with name "test-network-3" with 1 CIDR range:  10.10.30.0/24

The networks inside the network.csv file will look like this: 

test-network,professional,10.10.10.0/24,10.10.11.0/24,10.10.12.0/24<br />
test-network-2,essentials,10.10.20.0/24,10.10.21.0/24<br />
test-network-3,professional,10.10.30.0/24

#### These objects are required for external assets to be scanned externally by Alert Logic's Datacentre, post deployment. 
#### External Assets
Here you can add external assets which will be scanned from Alert Logic's Datacenter. 
You will need to add each FQDN or IP address to a respective .csv file, in the correct format.
For External Fully Qualified Domain Names:  
- Add the names to external-fqdns.csv.

#### Good Examples:
- "www.example.com"
- "www.google.com"

For External IP Addresses:
- Add the IP addresses to external-ips.csv.

#### Good Examples:
- "8.8.8.8"
- "8.8.4.4"

#### Bad Examples:
- "10.12.x.12\29"
- "10.1x.10.8/32"
- "8.x.1124.1"

### How to run the script: 
python3 create_dc_deployment.py
