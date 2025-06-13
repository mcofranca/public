import requests
import urllib3
import ipaddress
from datetime import datetime  as dt

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_src_file() -> bool:
    ''' 
    Checks if the source file fgt_src.txt exists in the specified directory.
    Checks if IP addresses and ports are provided and are correct in the source file.
    The source file should be located in public/Fortinet/fgtAPIfunctions/source/fgt_src.txt.

    This function is called to ensure that the source file is present and is correctly formatted before proceeding with any operations.
    Returns True if the file is valid, otherwise returns False.
    '''
    try:
        with open('public/Fortinet/fgtAPIfunctions/source/fgt_src.txt', 'r') as fgts:
            fgt_src = fgts.readlines()
            fgt_src_new = ''
            print('\n')

    except FileNotFoundError:
        print("Source file fgt_src.txt not found in public/Fortinet/fgtAPIfunctions/source/")
        return False
    
    if not fgt_src:
        print("Source file fgt_src.txt is empty.")
        return False
    if len(fgt_src) == 1 and fgt_src[0].strip() == '':
        print("Source file fgt_src.txt contains only an empty line.")
        return False
    
    result = False
    for i,line in enumerate(fgt_src):
        if ':' in line:
            fgt_ip, fgt_port = line.split(':')
            fgt_ip = fgt_ip.strip()
            fgt_port = fgt_port.strip()
            try:
                ipaddress.ip_address(fgt_ip)
            except ValueError:
                print(f"Invalid IP address in source file: line {i+1}, {fgt_ip}")
                continue
            if not fgt_port.isdigit():
                print(f"Invalid port in source file: line {i+1}, {fgt_port}")
                continue
            else:
                fgt_port = int(fgt_port)
                if fgt_port < 1 or fgt_port > 65535:
                    print(f"Port number out of range in source file: line {i+1}, {fgt_port}")
                    continue
                else:
                    result = True
                    print(f"Valid entry found: line {i+1}, {fgt_ip}:{fgt_port}")
                    fgt_src_new += f"\n{fgt_ip}:{fgt_port}"
        else:
            fgt_ip = line.strip()
            try:
                ipaddress.ip_address(fgt_ip)
                result = True
                fgt_src_new += f"\n{fgt_ip}"
                print(f"Valid IP address found: line {i+1}, {fgt_ip} (default port 10443 will be used)")
            except ValueError:
                print(f"Invalid IP address in source file: line {i+1}, {fgt_ip}")
    if not result:
        print("Source file fgt_src.txt contains only invalid IP addresses or ports.")
        return False
    else:
        with open('public/Fortinet/fgtAPIfunctions/source/fgt_src.txt', 'w') as fgts:
            fgts.write(fgt_src_new.strip())

    print("Source file fgt_src.txt is valid.")
    return True

def login(fgt_ip, username, secret, port=10443) -> tuple:
    ''' 
    The logout function  should be called at the end of the script to ensure proper session termination.
    Logs in to FortiGate and returns the session and headers required for authentication.
    This function is called at the beginning of the script to establish a session with the FortiGate device.
    It is important to note that the login function should be called only once at the beginning of the script.
    The FortiGate IP, Username, and Secret are passed as string arguments to the function.
    '''

    # Defining Session parameters
    session = requests.Session()
    urlbase = f"http://{fgt_ip}" if port == 80 else f"https://{fgt_ip}:{port}"

    urllogin = urlbase + "/logincheck"
    print(f"Logging in to FortiGate at {urllogin}")
    auth_data = {'username': username, 'secretkey': secret}

    # Session post
    try:
        login_headers = {"Content-Type": "text/plain"}
        response = session.post(urllogin, data=auth_data, headers=login_headers, verify=False)
        if not response.cookies.get_dict():
            print("Login Failed: No cookies received in response.")
            print("Status Code:", response.status_code)
            return None, None
        else:
            print("Login successful")
            print("Status Code:", response.status_code)
    except requests.RequestException as e:
        print("Error during login:", e)
        return None, None

# Capturing the session cookie
    if response is not None:
        cookies = response.cookies
    # Converting the session cookie to a dictionary
        cookies_dict = requests.utils.dict_from_cookiejar(cookies)
    else:
        cookies_dict = {}


# Extracting the CSRF token from the cookie
    csrftoken = None
    for secret in cookies_dict:
        if secret.startswith("ccsrftoken"):
            csrftoken = cookies_dict[secret]
            break

    if csrftoken is not None:
    # Remove extra quotes if they exist
        csrftoken = csrftoken.strip('"')
    else:
        print("CSRF token not found in cookies!")
        csrftoken = ""

# Adding the CSRF token to the headers and removing Content-Type
    headers = {}
    headers["X-CSRFToken"] = csrftoken

    # Do NOT set Content-Type globally on session
    return session, headers

def user_api(fgt_ip, api_key, port=10443) -> tuple:
    """
    This function is used to test the FortiGate API using the provided API key.
    It makes GET requests to two different endpoints and prints the response status and data.
    returns True if the API call is successful, otherwise returns False.
    Parameters:
    - fgt_ip: The IP address of the FortiGate device.
    - api_key: The API key used for authentication.
    """

    # Defining Session parameters
    session = requests.Session()
    url_base = f"http://{fgt_ip}" if port == 80 else f"https://{fgt_ip}:{port}"
    url1 = f'{url_base}/api/v2/monitor/system/status'
    url2 = f'{url_base}/api/v2/cmdb/system/settings'
    headers = {'Authorization': f'Bearer {api_key}'}



    # Testing the first endpoint API call
    print("Testing API call to:", url1)
    txt_api_admin_data = f"Test 1 URL: {url1}"
    try:
        response = session.get(url1, headers=headers, verify=False)
    except requests.RequestException as e:
        print("Error during API call:\n", e)
        txt_api_admin_data += f"\nTest 1 Error: {e}"
        return False, txt_api_admin_data


    if response.status_code == 200:
        print("Test 1 API call successful")
        txt_api_admin_data += f"\nTest 1 Response data: {response.text}"

    else:
        print("API call failed")
        print("Response code:", response.status_code)
        txt_api_admin_data += f"\nTest 1 Response code: {response.status_code}"

        return False, txt_api_admin_data

    # Testing the second endpoint API call
    print("Testing API call to:", url2)
    response = session.get(url2, headers=headers, verify=False)

    if response.status_code == 200:
        print("Test 2 API call successful")
        txt_api_admin_data += f"\nTest 2 URL: {url2}\n"
        txt_api_admin_data += f"\nTest 2 Response data:\n{response.text}"
        return True, txt_api_admin_data
    else:
        print("API call failed")
        print("Response code:", response.status_code)
        txt_api_admin_data += f"\nTest 2 Response code: {response.status_code}"

    return False, txt_api_admin_data

def logout(fgt_ip, session, headers, port=10443) -> None: 
    ''' 
    Performs logout from FortiGate.
    The login function should be called only once at the beginning of the script.
    This function is called at the end of the script to ensure proper session termination.
    It is important to note that the logout function should be called only if the session is valid.
    The session , Fortigate IP and headers are passed as arguments to the function.
    The function checks if the session and headers are valid before attempting to log out.

    '''

    urlbase = f"http://{fgt_ip}" if port == 80 else f"https://{fgt_ip}:{port}"
    urllogout = urlbase + "/logout"

    if session is None:
        print("Session is invalid, cannot perform logout.")
        return

    if headers is None:
        print("Headers are invalid, cannot perform logout.")
        return
    try:
        # Ensure headers contain the CSRF token
        if "X-CSRFToken" not in headers:
            cookies_dict = requests.utils.dict_from_cookiejar(session.cookies)
            for secret in cookies_dict:
                if secret.startswith("ccsrftoken"):
                    headers["X-CSRFToken"] = cookies_dict[secret].strip('"')
                    break

        logout_response = session.get(urllogout, headers=headers, verify=False)
        if logout_response.status_code == 200:
            print("Logout successful")
        else:
            print("Logout failed")
    except requests.RequestException as e:
        print("Error during logout:", e)
        # logout_response = None

def save_response_data(fgt_ip, txt) -> None:
    ''' 
    Saves the response data to a text file in the public/results folder.
    This function is called to save the response data from the API calls to a text file for further analysis.
    The response data is passed as an argument to the function.
    '''

    # Save the response data to a text file in results folder
    print(f"Saving response data to public/Fortinet/fgtAPIfunctions/results/APITEST_{fgt_ip}.txt")
    with open(f"public/Fortinet/fgtAPIfunctions/results/APITEST_{fgt_ip}.txt", 'a') as file:
        file.write(txt)

def file_dict() -> list:
    ''' 
    Reads the fgt_src.txt file and returns a dictionary with FortiGate IPs and ports as keys and empty strings as values.
    This function is called to read the FortiGate IPs from the fgt_src.txt file.
    The function returns a dictionary with FortiGate IPs as keys and empty strings as values.
    '''
    fgt_list = []
    with open('public/Fortinet/fgtAPIfunctions/source/fgt_src.txt', 'r') as fgts:
        fgt_src = fgts.readlines()
        for line in fgt_src:
            fgt_ip = line.split(':')[0].strip() if ':' in line else line.strip()
            fgt_port = line.split(':')[1].strip() if ':' in line else "10443"

            if fgt_ip:  # Check if the line is not empty
                fgt_dict = {"fgt_ip": fgt_ip, "fgt_port": fgt_port}
                fgt_list.append(fgt_dict)

    return fgt_list

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
            print('\nTest 1: URL:', urlbase + "/api/v2/cmdb/system/settings")
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
    # result = False
    return result

# print(user_api("192.168.1.1", "api_key"))
# print(testAPIconnection("192.168.15.29", "admin", "admin", 80))