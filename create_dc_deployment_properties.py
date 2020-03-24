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
# In a .csv file, you can specify what networks you would like added to the Alert Logic Console.
# In the root folder of this script, you will see an example called networks.csv to use.
# Please note that these networks need to have a particular format: 
#     - All networks need to be comma separated values
#     - The first value in each list must be the Network Name
#     - The CIDR ranges for that network must follow on from the network name
#
# Example (Network Name - Arbitary name for added network):
#     test-network,10.10.10.0/24,10.10.11.0/24,10.10.12.0/24
#     test-network-2,10.10.20.0/24,10.10.21.0/24
#     test-network-3,10.10.30.0/24
#      <More Networks if needed> 
network_csv_file = "networks.csv"

# The protection level you would like to set on each of the protected regions/VPC's above. 
# Must be either "Essentials" or "Professional"
entitlement = "Professional"

# External Assets
# Here you can add external assets which will be scanned from Alert Logic's Datacenter. 
# You will need to add each DNS name or IP address in the following lists, in the correct format.
# Examples: 
#     external_dns_names=["www.example.com","www.google.com"]
#     external_ip_addresses=["8.8.8.8", "8.8.4.4"]
external_dns_names=[]
external_ip_addresses=[]

