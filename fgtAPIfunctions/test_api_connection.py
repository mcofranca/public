from auth_functions import testAPIconnection as testAPI
import getpass as gp

# endpoint parameters
with open('public/address.txt', 'r') as f:
    lines = f.readlines()
    fgt_ip = lines[0].strip()

username = input("Enter the username: ")
secret = gp.getpass("Enter the password or API key: ")


# Testing Connection with the FortiGate
testapi = testAPI(fgt_ip, username, secret)
if testapi == False:
    print("Failed to establish connection with FortiGate.")
else:
    print("Connection with FortiGate established successfully.")

