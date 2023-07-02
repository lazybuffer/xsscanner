import requests, time
from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin

# manual text colored
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

print(bcolors.OKGREEN+bcolors.BOLD+"\nIf you wanted to do Extend Level [ --level=2 ]"+bcolors.ENDC)
print(bcolors.OKGREEN+bcolors.BOLD+"Run python3 xsscan.py [ url ] --level=2\n"+bcolors.ENDC)

def get_all_forms(url):
    """Given a `url`, it returns all forms from the HTML content"""
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):
    """
    This function extracts all possible useful information about an HTML `form`
    """
    details = {}
    # get the form action (target url)
    action = form.attrs.get("action", "").lower()
    # get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    # get all the input details such as type and name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


def submit_form(form_details, url, value):
    """
    Submits a form given in `form_details`
    Params:
        form_details (list): a dictionary that contain form information
        url (str): the original URL that contain that form
        value (str): this will be replaced to all text and search inputs
    Returns the HTTP Response after form submission
    """
    # construct the full URL (if the url provided in action is relative)
    target_url = urljoin(url, form_details["action"])
    # get the inputs
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        # replace all text and search values with `value`
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value")
        if input_name and input_value:
            # if input name and value are not None, 
            # then add them to the data of form submission
            data[input_name] = input_value

    print(bcolors.WARNING+f"[ + ]"+bcolors.ENDC+f" Submitting malicious payload to {target_url}")
    print(bcolors.WARNING+f"[ + ]"+bcolors.ENDC+f" Data: {data}")
    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        # GET request
        return requests.get(target_url, params=data)

# # level incress one. 
def scan_xss(url):
    """
    Given a `url`, it prints all XSS vulnerable forms and 
    returns True if any is vulnerable, False otherwise
    """
	# get all the forms from the URL
    forms = get_all_forms(url)
    print(bcolors.WARNING+f"[ + ]"+bcolors.ENDC+bcolors.BOLD+f" Detected {len(forms)} forms on {url}."+bcolors.ENDC)
    js_script = "<Script>alert('hi')</scripT>"
	# returning value
    is_vulnerable = False
	# iterate over all forms
    for form in forms:
        form_details = get_form_details(form)
        content = submit_form(form_details, url, js_script).content.decode()
        if js_script in content:
            print(bcolors.WARNING+f"[ + ]"+bcolors.ENDC+bcolors.BOLD+f" XSS Detected on {url}"+bcolors.ENDC)
            time.sleep(2)
            print(bcolors.WARNING+f"\n[ + ]"+bcolors.ENDC+f" Form details:")
            print(bcolors.FAIL+"⣾⣿⣿⣿⣿⣾⣿⣿⣿⣿⣿⣿⣿⣷⣶⣶⣷⣶⣶⣾⣿⣿⣿⣿⣾⣿⣿⣿⣿⣿⣿⣿⣷⣶⣶⣷⣶⣶"+bcolors.ENDC+"\n ")
            pprint(form_details)
            print(" \n"+bcolors.FAIL+"⣾⣿⣿⣿⣿⣾⣿⣿⣿⣿⣿⣿⣿⣷⣶⣶⣷⣶⣶⣾⣿⣿⣿⣿⣾⣿⣿⣿⣿⣿⣿⣿⣷⣶⣶⣷⣶⣶"+bcolors.ENDC+"\n ")
            is_vulnerable = True
        # won't break because we want to print other available vulnerable forms
        return is_vulnerable

if __name__ == "__main__":
    import sys 
    import level_two

    try:
        url = sys.argv[1]
        print(scan_xss(url))
        cmmand = sys.argv[2]
    except:
        pass
    
    try:
        if cmmand == "--level=2":
            print(bcolors.WARNING+f"\n[ + ]"+bcolors.ENDC+bcolors.BOLD+" Extending Scanner Level 2\n"+bcolors.ENDC)
            time.sleep(2)
            print(level_two.scan_xss(url))
    except:
        pass

