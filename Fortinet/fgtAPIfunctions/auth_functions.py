import requests
import urllib3
from datetime import datetime  as dt

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def login(fgt_ip, username, secret) -> tuple:
    ''' 
    The logout function  should be called at the end of the script to ensure proper session termination.
    Logs in to FortiGate and returns the session and headers required for authentication.
    This function is called at the beginning of the script to establish a session with the FortiGate device.
    It is important to note that the login function should be called only once at the beginning of the script.
    The FortiGate IP, Username, and Secret are passed as string arguments to the function.
    '''

    # Defining Session parameters
    session = requests.Session()
    urlbase = "http://" + fgt_ip # Fortigate in the lab is not licensed for HTTPS
    urllogin = urlbase + "/logincheck"
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

def user_api(fgt_ip, api_key) -> tuple:
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
    url1 = f'http://{fgt_ip}/api/v2/monitor/system/status'
    url2 = f'http://{fgt_ip}/api/v2/cmdb/system/settings'
    headers = {'Authorization': f'Bearer {api_key}'}

    txt_api_admin_data = "Response data:"

    # Testing the first endpoint API call
    print("\nTesting API call to:", url1)
    txt_api_admin_data += f"\nTest 1 URL: {url1}\n"
    response = session.get(url1, headers=headers, verify=False)


    if response.status_code == 200:
        print("Test 1 API call successful")
        txt_api_admin_data += f"\nTest 1 Response data:\n{response.text}"

    else:
        print("API call failed")
        print("Response code:", response.status_code)
        txt_api_admin_data += f"\nTest 1 Response code: {response.status_code}"

        return False, txt_api_admin_data

    # Testing the second endpoint API call
    print("\nTesting API call to:", url2)
    response = session.get(url2, headers=headers, verify=False)

    if response.status_code == 200:
        print("Test 2 API call successful")
        txt_api_admin_data += f"\n\nTest 2 URL: {url2}\n"
        txt_api_admin_data += f"Test 2 Response data:\n{response.text}"
        return True, txt_api_admin_data
    else:
        print("API call failed")
        print("Response code:", response.status_code)
        txt_api_admin_data += f"\nTest 2 Response code: {response.status_code}"

    return False, txt_api_admin_data

def logout(fgt_ip, session, headers) -> None:
    ''' 
    Performs logout from FortiGate.
    The login function should be called only once at the beginning of the script.
    This function is called at the end of the script to ensure proper session termination.
    It is important to note that the logout function should be called only if the session is valid.
    The session , Fortigate IP and headers are passed as arguments to the function.
    The function checks if the session and headers are valid before attempting to log out.

    '''

    urlbase = "http://" + fgt_ip
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
    print(f"\nSaving response data to public/Fortinet/fgtAPIfunctions/results/{fgt_ip}_{dt.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt")
    with open(f"public/Fortinet/fgtAPIfunctions/results/{fgt_ip}_{dt.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt", 'w') as file:
        file.write(txt)

def testAPIconnection(fgt_ip, username='', secret='') -> bool:
    ''' 
    Tests the session by making a GET request to the FortiGate API.
    This function is called to verify if the session is still valid and can be used for further API calls.
    The session and headers are passed as arguments to the function.
    The function checks if the session and headers are valid before attempting to make a GET request.
    '''

    bool_api_admin_result, txt_api_admin_data = user_api(fgt_ip, secret)

    txt_api_admin_data = f"Fortigate IP: {fgt_ip}\n" + txt_api_admin_data

    if bool_api_admin_result == True:
        print("API call successful with the key")
        save_response_data(fgt_ip, txt_api_admin_data)
        return True
    else:
        print("API call failed with the key")
        txt_api_admin_data += "\nResponse Data:"


    urlbase = "http://" + fgt_ip
    session, headers = login(fgt_ip, username, secret)

    txt_login_data = f"Fortigate IP: {fgt_ip}\n"

    #Test 1
    try:
        if session is not None:
            response = session.get(urlbase + "/api/v2/cmdb/system/settings", headers=headers, verify=False)
            print('\nTest 1 : URL:\n', urlbase + "/api/v2/cmdb/system/settings")
            txt_login_data += f"Test 1 URL: {urlbase + '/api/v2/cmdb/system/settings'}\n"

            if response.status_code == 200:
                print("Session is valid")
                txt_login_data += f"Test 1 data:\n{response.text}\n"
            else:
                print("Session is invalid")
                txt_login_data += f"Test 1 data:\n{response.status_code}\n"
                logout(fgt_ip, session, headers)
                return False
                
        else:
            print("Session is invalid, cannot perform GET request.")
            txt_login_data += "Session is invalid, cannot perform GET request.\n"
            response = None
            logout(fgt_ip, session, headers)
            return False
        
    except requests.RequestException as e:
        print("Error during session test:", e)
        txt_login_data += f"Error during session test: {e}\n"
        response = None
        logout(fgt_ip, session, headers)
        save_response_data(fgt_ip, txt_login_data)
        return False

    #Test 2
    try:
        if session is not None:
            response = session.get(urlbase + "/api/v2/monitor/system/status", headers=headers, verify=False)
            print(f'\nTest 2: URL: {urlbase + "/api/v2/monitor/system/status"}')
            txt_login_data += f"Test 2 URL: {urlbase + '/api/v2/monitor/system/status'}\n"

            if response.status_code == 200:
                print("Session is valid")
                print("Connection with username and password successful")

                txt_login_data += f"Test 2 monitor response:\n{response.text}\n"
                logout(fgt_ip, session, headers)
                save_response_data(fgt_ip, txt_login_data)
                return True 
            
            else:
                print("Session is invalid")
                txt_login_data += f"Test 2 monitor response: {response.status_code}\n"
                logout(fgt_ip, session, headers)
                save_response_data(fgt_ip, txt_login_data)
                return False
                
        else:
            print("Session is invalid, cannot perform GET request.")
            txt_login_data += "Session is invalid, cannot perform GET request.\n"
            response = None
            logout(fgt_ip, session, headers)
            save_response_data(fgt_ip, txt_login_data)
            return False
        
    except requests.RequestException as e:
        print("Error during session test:", e)
        txt_login_data += f"Error during session test: {e}\n"
        response = None

    logout(fgt_ip, session, headers)

    # Save the response data to a text file in results folder
    print(f"\nSaving response data to public/results/{dt.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt")
    save_response_data(fgt_ip, txt_login_data)
    return False
