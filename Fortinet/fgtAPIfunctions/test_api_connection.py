from auth_functions import testAPIconnection as testAPI
import getpass as gp

# endpoint parameters
with open('public/Fortinet/fgtAPIfunctions/source/fgt_list.txt', 'r') as fgts:
    fgt_list = [line.strip() for line in fgts]

username = input("Enter the username: ")
secret = gp.getpass("Enter the password or API key: ")


# Testing Connection with the FortiGate
for fgt in fgt_list:
    fgt_ip = fgt.strip()
    print(f"\nFortiGate IP: {fgt_ip}")
    testapi = testAPI(fgt_ip, username, secret)
    if testapi == False:
        print("Failed to establish connection with FortiGate.")
    else:
        print("Connection with FortiGate established successfully.")


