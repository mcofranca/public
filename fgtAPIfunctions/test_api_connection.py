from auth_functions import testAPIconnection as testAPI
import getpass as gp

# endpoint parameters
with open('public/source/address.txt', 'r') as fgts:
    fgt_list = [line.strip() for line in fgts]

username = input("Enter the username: ")
secret = gp.getpass("Enter the password or API key: ")


# Testing Connection with the FortiGate
for fgt in fgt_list:
    fgt_ip = fgt.strip()
    testapi = testAPI(fgt_ip, username, secret)
    if testapi == False:
        print("\nFailed to establish connection with FortiGate.")
    else:
        print("\nConnection with FortiGate established successfully.")
        print(f"FortiGate IP: {fgt_ip}")

