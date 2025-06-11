# from auth_functions import testAPIconnection as testAPI
import auth_functions as fgt_func
import getpass as gp

# endpoint parameters
# with open('public/Fortinet/fgtAPIfunctions/source/fgt_src.txt', 'r') as fgts:
#     fgt_list = [line.strip() for line in fgts]

fgt_list = fgt_func.file_dict()

username = input("Enter the username (blank if not required): ")
secret = gp.getpass("Enter the password or API key: ")


# Testing Connection with the FortiGate
for fgt in fgt_list:
    fgt_ip = fgt["fgt_ip"]
    fgt_port = int(fgt["fgt_port"])
    print(f"\nFortiGate IP: {fgt_ip}, Port: {fgt_port}")
    testapi = fgt_func.testAPIconnection(fgt_ip, username, secret, port=fgt_port)
    if testapi == False:
        print("Failed to establish connection with FortiGate.")
    else:
        print("Connection with FortiGate established successfully.")


