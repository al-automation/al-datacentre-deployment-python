############################################################
#####  Configuration settings for Deployment Creation  #####
############################################################

# This configuration file is used to set all required 
# variables in order to create a data center deployment into 
# an Alert Logic Customer ID. 

## Authentication Information
# Here you can specify either a username/password, or 
# access/secret keys (that can be generated through the 
# Alert Logic Console), in order to obtain an authentication 
# token to authorise all following API requests. The script 
# will use API Keys first if they are present 

# The Username & Password you would like to use for authentication: 
alert_logic_username = ''
alert_logic_password = ''

# The API Keys you would like to use for authentication 
# (https://docs.alertlogic.com/prepare/access-key-management.htm)
alert_logic_access_apikey = ''
alert_logic_secret_apikey = ''

## Main Configuration
# The Alert Logic Customer ID you would like to create the deployment into: 
alert_logic_cid = ""

# The name you would like the deployment in the Alert Logic Console created with:
alert_logic_deployment_name = ""

# Protected Networks
# Here you can specify what networks you would like added to the Alert Logic Console. 
# Please note that these networks need to have a particular format: 
#     - All networks need to be added as a list, inside the existing networks = [] list
#     - The first value in each list must be the Network Name
#     - The CIDR ranges for that network must follow on from the network name in the list format
#     - The lists must be in a python list format (values surrounded by quotes, comma separated)
# Example (Network Name - Arbitary name for added network):
#     networks = [
#     ["Network Name 1", "192.168.16.0/24", "192.168.128.0/24", "172.24.0.0/16"],.
#     ["Network Name 2", "10.10.0.0/16"],
#     [ <More Networks if needed> ].
#     ]

networks = [
]

# The protection level you would like to set on each of the protected regions/VPC's above. 
# Must be either "Essentials" or "Professional"
entitlement = ""

# External Assets
# Here you can add external assets which will be scanned from Alert Logic's Datacenter. 
# You will need to add each DNS name or IP address in the following lists, in the correct format.
# Examples: 
#     external_dns_names=["www.example.com","www.google.com"]
#     external_ip_addresses=["8.8.8.8", "8.8.4.4"]

external_dns_names=[]
external_ip_addresses=[]

