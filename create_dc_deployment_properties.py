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
#     test-network,professional,10.10.10.0/24,10.10.11.0/24,10.10.12.0/24
#     test-network-2,essentials,10.10.20.0/24,10.10.21.0/24
#     test-network-3,professional,10.10.30.0/24
#      <More Networks if needed>

network_csv_file = "networks.csv"

# External Assets
# Here you can add external assets which will be scanned from Alert Logic's Datacenter. 
# You will need to add each FQDN or IP address to a respective .csv file, in the correct format.
# For External Fully Qualified Domain Names:  
#     - Add the names to external-fqdns.csv.
# Good Examples:
#     "www.example.com"
#     "www.google.com"
#
# For External IP Addresses:
#     - Add the IP addresses to external-ips.csv.
# Good Examples:
#     "8.8.8.8"
#     "8.8.4.4"
# Bad Examples:
#     "10.12.x.12\29"
#     "10.1x.10.8/32"
#     "8.x.1124.1"

external_dns_names=[]
external_ip_addresses=[]

