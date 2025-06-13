# from auth_functions import testAPIconnection as testAPI
import auth_functions as fgt_func
import getpass as gp

# endpoint parameters
# with open('public/Fortinet/fgtAPIfunctions/source/fgt_src.txt', 'r') as fgts:
#     fgt_list = [line.strip() for line in fgts]



username = input("Enter the username (blank if not required): ")
secret = gp.getpass("Enter the password or API key: ")

    # Check if the source file exists and is valid
if not fgt_func.check_src_file():
    print("Source file fgt_src.txt has not valid entries or does not exist.")
    exit(1)
else:
    fgt_list = fgt_func.file_dict()

    # Testing Connection with the FortiGate
    for fgt in fgt_list:
        fgt_ip = fgt["fgt_ip"]
        fgt_port = int(fgt["fgt_port"])
        print(f"\n{'-'*40}\nFortiGate IP: {fgt_ip}, Port: {fgt_port}")
        testapi = fgt_func.testAPIconnection(fgt_ip, username, secret, port=fgt_port)
        if testapi == False:
            print(f"Failed to establish connection with FortiGate.\n{'-'*40}")
        else:
            print(f"Connection with FortiGate established successfully.\n{'-'*40}")


