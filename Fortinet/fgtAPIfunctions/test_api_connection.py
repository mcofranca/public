# from auth_functions import testAPIconnection as testAPI
import getpass as gp
import requests
from datetime import datetime as dt
from auth_functions import login, logout, user_api, save_response_data, check_src_file, src_file_to_dict


username = input("Enter the username (blank if not required): ")
secret = gp.getpass("Enter the password or API key: ")

def testAPIconnection(fgt_ip, username='', secret='', port=10443) -> bool:
    ''' 
    Tests the session by making a GET request to the FortiGate API.
    This function is called to verify if the session is still valid and can be used for further API calls.
    The session and headers are passed as arguments to the function.
    The function checks if the session and headers are valid before attempting to make a GET request.
    '''
    now = dt.now().strftime('%Y-%m-%d %H:%M:%S')

    logs = f"\n{'-'*40}\n"
    logs += f"{now} - Fortigate IP: {fgt_ip} - Port: {port}\n"

    # Testing the API with the provided API key
    if not secret:
        print("No API key provided, cannot perform API tests.")
        txt_api_admin_data = f"Fortigate IP: {fgt_ip}\nNo API key provided, cannot perform API tests.\n"
        logs += txt_api_admin_data
    else:
        bool_api_admin_result, txt_api_admin_data = user_api(fgt_ip, secret, port=port)
        print("Testing API with the provided API key")
        if bool_api_admin_result == True:
            print("API call successful with the key")
            logs += txt_api_admin_data
            save_response_data(fgt_ip, logs)
            return True
        else:
            print("API call failed with the key")
            txt_api_admin_data += "\nResponse Data: API call failed with the key"
            logs += txt_api_admin_data

    # If username and secret are provided, proceed with login
    if not username:
        print("No username provided, cannot log in.")
        txt_login_data = f"Fortigate IP: {fgt_ip}\nNo username provided, cannot log in.\n"
        logs += txt_login_data
        save_response_data(fgt_ip, logs)
        return False
    

    txt_login_data = ""
    urlbase = f"http://{fgt_ip}" if port == 80 else f"https://{fgt_ip}:{port}"
    print(f"Testing connection with FortiGate at {urlbase}")
    session, headers = login(fgt_ip, username, secret, port=port)

    if session is None or headers is None:
        print("Login failed, cannot perform API tests.")
        txt_login_data = f"\nLogin failed, cannot perform API tests."
        logs += txt_login_data
        save_response_data(fgt_ip, logs)
        return False

    #Test 1
    try:
        if session is not None:
            response = session.get(urlbase + "/api/v2/cmdb/system/settings", headers=headers, verify=False)
            print('Test 1: URL:', urlbase + "/api/v2/cmdb/system/settings")
            txt_login_data += f"\nTest 1 URL: {urlbase + '/api/v2/cmdb/system/settings'}"

            if response.status_code == 200:
                print("Session is valid")
                txt_login_data += f"\nTest 1 data:\n{response.text}"
                logs += txt_login_data
            else:
                print("Session is invalid")
                txt_login_data += f"\nTest 1 data:\n{response.status_code}"
                logout(fgt_ip, session, headers)
                logs += txt_login_data
                result = False
                
        else:
            txt_login_data += "\nSession is invalid, cannot perform GET request."
            response = None
            logout(fgt_ip, session, headers)
            logs += txt_login_data
            result = False

    except requests.RequestException as e:
        print("Error during session test:", e)
        txt_login_data += f"\nError during session test: {e}\n"
        response = None
        logout(fgt_ip, session, headers)
        logs += txt_login_data
        result = False

    #Test 2
    try:
        if session is not None:
            response = session.get(urlbase + "/api/v2/monitor/system/status", headers=headers, verify=False)
            print(f'Test 2: URL: {urlbase + "/api/v2/monitor/system/status"}')
            txt_login_data += f"\nTest 2 URL: {urlbase + '/api/v2/monitor/system/status'}\n"

            if response.status_code == 200:
                print("Session is valid")
                print("Connection with username and password successful")

                txt_login_data += f"\nTest 2 monitor response:\n{response.text}\n"
                logout(fgt_ip, session, headers)
                logs += txt_login_data
                result = True

            else:
                print("Session is invalid")
                txt_login_data += f"\nTest 2 monitor response: {response.status_code}\n"
                logout(fgt_ip, session, headers)
                logs += txt_login_data
                result = False

        else:
            txt_login_data += f"\nSession is invalid, cannot perform GET request.\n"
            response = None
            logout(fgt_ip, session, headers)
            logs += txt_login_data
            result = False

    except requests.RequestException as e:
        print("Error during session test:", e)
        txt_login_data += f"\nError during session test: {e}\n"
        result = False
        response = None

    logout(fgt_ip, session, headers, port=port)

    # Save the response data to a text file in results folder
    logs += txt_api_admin_data + "\n" + txt_login_data
    save_response_data(fgt_ip, logs)
    return result

    # Check if the source file exists and is valid
if not check_src_file():
    print("Source file fgt_src.txt has not valid entries or does not exist.")
    exit(1)
else:
    fgt_list = src_file_to_dict()

    # Testing Connection with the FortiGate
    for fgt in fgt_list:
        fgt_ip = fgt["fgt_ip"]
        fgt_port = int(fgt["fgt_port"])
        print(f"\n{'-'*40}\nFortiGate IP: {fgt_ip}, Port: {fgt_port}")
        testapi = testAPIconnection(fgt_ip, username, secret, port=fgt_port)
        if testapi == False:
            print(f"Failed to establish connection with FortiGate.\n{'-'*40}")
        else:
            print(f"Connection with FortiGate established successfully.\n{'-'*40}")



