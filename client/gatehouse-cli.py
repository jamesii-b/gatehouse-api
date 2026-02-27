#!/usr/bin/python3
import base64
from datetime import datetime
import os
import webbrowser
import requests
import argparse
import jwt
import json
import datetime
import pytz
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qsl
from dotenv import load_dotenv
from sshkey_tools.cert import SSHCertificate
import logging
import coloredlogs
import subprocess
import base64

# Load environment variables from the .env file
load_dotenv()

# Get the API_URL from the environment variables
SIGN_URL = os.getenv("SIGN_URL", "http://localhost:1234")
LISTENER_HOST_NAME = "127.0.0.1"
LISTENER_SERVER_PORT = 8250
CA_API_HOST = "127.0.0.1"
CA_SERVER_PORT = 1234
CACHE_FILE = 'token_cache.json' ###need to change it to secure location and permissions if used in production
CERT_FILE_PATH = "/tmp/ssl-cert"
CHALLENGE_FILE_PATH = "/tmp/challenge.txt"
CHALLENGE_SIG_FILE_PATH = "/tmp/challenge.txt.sig"

# Configure logger
logger = logging.getLogger(__name__)
coloredlogs.install(level='DEBUG', logger=logger, fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


class MyServer(BaseHTTPRequestHandler):
    def do_GET(self):
        """Handle GET requests and process token reception."""
        global server_done, token
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(bytes("<html><head><title>OIDC Workflow Tool</title></head>", "utf-8"))
        self.wfile.write(bytes("<body><p>The token has been received</p>", "utf-8"))
        self.wfile.write(bytes("<p>Window closing in <span id='countdown'>5</span> seconds...</p>", "utf-8"))
        self.wfile.write(bytes("<script>var count = 5; setInterval(function() { count--; document.getElementById('countdown').textContent = count; if (count === 0) window.close(); }, 1000);</script>", "utf-8"))
        self.wfile.write(bytes("</body></html>", "utf-8"))
        
        parsed_url = urlparse(self.path)
        query_data = dict(parse_qsl(parsed_url.query))
        token = query_data.get('token')

        if token:
            server_done = True
            logger.info("Token received")
            save_token_to_cache(token)

    def log_message(self, format, *args):
        """Log messages using the logger instead of stdout."""
        logger.info("%s - %s" % (self.client_address[0], format % args))


def load_token_from_cache():
    """Load the token from the cache file."""
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r') as f:
            data = json.load(f)
            if 'token' in data:
                return data['token']
    return None

def save_token_to_cache(token):
    """Save the token to the cache file."""
    with open(CACHE_FILE, 'w') as f:
        json.dump({'token': token}, f)

def clear_token_cache():
    """Remove the cached token file."""
    if os.path.exists(CACHE_FILE):
        os.remove(CACHE_FILE)
        logger.info("Cached token removed.")
    else:
        logger.info("No cached token found.")

def decode_and_validate_token(token):
    """Decode the JWT and validate its claims."""
    try:
        decoded_token = jwt.decode(token, options={"verify_signature": False})
        logger.debug("debug_jwt - Decoded token ok")

        iat = decoded_token.get('iat')
        exp = decoded_token.get('exp')

        if iat is None or exp is None:
            raise ValueError("Token must contain 'iat' and 'exp' claims.")

        iat_utc = datetime.datetime.fromtimestamp(iat, pytz.UTC).isoformat()
        exp_utc = datetime.datetime.fromtimestamp(exp, pytz.UTC).isoformat()

        logger.debug(f"debug_jwt - iat (UTC ISO): {iat_utc}")
        logger.debug(f"debug_jwt - exp (UTC ISO): {exp_utc}")

        now = datetime.datetime.now(pytz.UTC)

        if datetime.datetime.fromtimestamp(iat, pytz.UTC) > now:
            logger.debug(f"debug_jwt - Token 'iat' is after the current time.")

        if datetime.datetime.fromtimestamp(exp, pytz.UTC) < now:
            logger.debug(f"debug_jwt - Token 'exp' is before the current time.")
            return False  # Token has expired

        return True  # Token is valid

    except Exception as e:
        logger.error(f"Token validation failed: {e}")
        return False

def request_token():
    global server_done, token
    server_done = False
    logger.info("Starting request_token process.")

    # Attempt to load the token from the cache
    token = load_token_from_cache()
    logger.debug("Token loaded from cache: %s", token)

    # Validate the cached token, if it exists
    if token and decode_and_validate_token(token):
        logger.info("Cached token is valid. Using cached token.")
        return token

    logger.info("No valid cached token found, proceeding to request a new token.")
    token = ""

    # Prepare the redirect URL for the token request
    redirect_url = f"http://{LISTENER_HOST_NAME}:{LISTENER_SERVER_PORT}/?token="
    logger.info("Redirect URL: %s", redirect_url)

    # Construct the token request URL
    token_url = f"{SIGN_URL}/token_please?redirect_url={redirect_url}"
    logger.info("Token request URL: %s", token_url)

    # Start the web server to handle the token response
    logger.debug("Starting the HTTP server on %s:%d", LISTENER_HOST_NAME, LISTENER_SERVER_PORT)
    webServer = HTTPServer((LISTENER_HOST_NAME, LISTENER_SERVER_PORT), MyServer)

    # Open the web browser to initiate the token request
    logger.info("Opening web browser to request token.")
    webbrowser.open(token_url, new=2)

    # Wait for the server to handle the request and receive the token
    logger.debug("Waiting for the token response...")
    while not server_done:
        webServer.handle_request()
        logger.debug("Server handled a request, server_done status: %s", server_done)

    logger.info("Token received: %s", token)
    return token

def get_activated_ssh_key():
    """Retrieve the list of SSH keys and return the first verified key."""
    try:
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        response = requests.get(f"{SIGN_URL}/api/ssh-keys", headers=headers)

        if response.status_code == 200:
            keys = response.json().get('ssh_keys', [])
            verified_keys = [key for key in keys if key['verified']]
            
            if not verified_keys:
                logger.error("No verified SSH keys found for the user.")
                exit(1)

            if len(verified_keys) > 1:
                logger.error("Multiple verified SSH keys found. Please specify CERT_ID.")
                exit(1)

            return verified_keys[0]['id']

        else:
            logger.error(f"Failed to retrieve SSH keys: {response.status_code} - {response.text}")
            exit(1)

    except Exception as e:
        logger.error(f"Error while retrieving SSH keys: {e}")
        exit(1)


def request_certificate():
    CERT_ID = os.getenv("CERT_ID") or get_activated_ssh_key()

    headers = {
        'content-type': 'application/json',
        "Authorization": "bearer " + token
    }
    
    payload = {
        'cert_id': CERT_ID
    }
    
    try:
        response = requests.post(f"{SIGN_URL}/sign_cert", json=payload, headers=headers)

        if response.status_code == 200:
            json_result = response.json()
            with open(CERT_FILE_PATH, 'w') as f:
                f.write(json_result['certificate'])
            logger.info(f"Certificate signed successfully, located at {CERT_FILE_PATH}")
            logger.info("You can login to your destination server with the following command")
            logger.info(f"\tssh user@server -o CertificateFile={CERT_FILE_PATH}")
        else:
            logger.error("Error in response from server")
            logger.error(f"Status code: {response.status_code}")
            logger.error(f"Response text: {response.text}")
    except Exception as e:
        logger.error(f"Error during certificate signing: {e}")

def generate_and_sign_challenge(ssh_key_file,key_id):
    """Generate a challenge text, sign it using the SSH key, and return the signature."""
    logger.debug(f"generate_and_sign_challenge - {ssh_key_file} {key_id}")
    #Fetch challenge text from API
    try:
        global token                                                                                                                                                        
        
        if not token:                                                                                                                                               
            raise EnvironmentError("TOKEN environment variable is not set")   
        headers = {
            'Authorization': f'Bearer {token}',                                                                                                                     
            "Content-Type": "application/json",
        }

        # Send the POST request
        response = requests.get(
            f"http://{CA_API_HOST}:{CA_SERVER_PORT}/api/ssh-key/{key_id}/validationData",
            headers=headers
        )
        if response.status_code!=200:
            logger.error(f"Server returned unexpected code {response.status_code}")
            return False
        
        challenge_text=response.json()['validationText']+"\n"
        
    except Exception as e:
        logger.error(f"Unable to fetch SSH Key validation data {e}")
        return False

    try:
        logger.debug(f"generate_and_sign_challenge - procesing challenge with text {challenge_text}")
        
        if os.path.exists(CHALLENGE_FILE_PATH):
            os.remove(CHALLENGE_FILE_PATH)
        if os.path.exists(CHALLENGE_SIG_FILE_PATH):
            os.remove(CHALLENGE_SIG_FILE_PATH)

        with open(CHALLENGE_FILE_PATH, 'w') as f:
            f.write(challenge_text)

        # Sign the challenge text using the SSH key
        result=subprocess.run(["ssh-keygen", "-Y", "sign", "-f", ssh_key_file, "-n", "file", CHALLENGE_FILE_PATH], check=True)
        logger.debug(f"generate_and_sign_challenge - {result}")
        # Read the signature
        with open(CHALLENGE_SIG_FILE_PATH, 'rb') as f:
            signature = base64.b64encode(f.read()).decode('utf-8')
            submit_signature_validation(signature,key_id)
        return signature
    except Exception as e:
        logger.error(f"Unable to sign the challenge reponse {e}")

def submit_signature_validation(signature, key_id):
    try:
        # Define the headers and payload
        global token                                                                                                                                                        
        
        if not token:                                                                                                                                               
            raise EnvironmentError("TOKEN environment variable is not set")   
        headers = {
            'Authorization': f'Bearer {token}',                                                                                                                     
            "Content-Type": "application/json",
        }
        logger.debug(f"submit_signature_validation - {signature}")
        payload = {
            "signature": signature
        }

        # Send the POST request
        response = requests.post(
            f"http://{CA_API_HOST}:{CA_SERVER_PORT}/api/ssh-key/{key_id}/validate",
            headers=headers,
            json=payload
        )

        # Print the response
        print(response.status_code)
        print(response.text)
    except Exception as e:
        logger.error(f"submit_signature_validation - Unable to submit the challenge response {e}")

def remove_ssh_key(key_id=None):
    """
    Remove an SSH key from the server. If key_id is None, list keys and prompt user to pick one.
    """
    global token

    if not token:
        raise EnvironmentError("TOKEN environment variable is not set")

    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

    # List keys first
    response = requests.get(f"{SIGN_URL}/api/ssh-keys", headers=headers)
    if response.status_code != 200:
        logger.error(f"Failed to list SSH keys: {response.status_code} - {response.text}")
        exit(1)

    keys = response.json().get('ssh_keys', [])
    if not keys:
        logger.info("No SSH keys found for your user.")
        return

    if key_id:
        # Delete specific key
        target = next((k for k in keys if k['id'] == key_id), None)
        if not target:
            logger.error(f"Key ID {key_id} not found in your profile.")
            exit(1)
        keys_to_delete = [target]
    else:
        # Show all keys and let user pick
        print("\nYour SSH keys:")
        for i, k in enumerate(keys):
            verified = "✓ verified" if k['verified'] else "✗ unverified"
            print(f"  [{i+1}] {k['id']}  {verified}  {k.get('description','')}  (added {k['created_at'][:10]})")
        print("  [a] Delete ALL keys")
        print("  [q] Quit")
        choice = input("\nEnter number to delete (or 'a' for all, 'q' to quit): ").strip().lower()

        if choice == 'q':
            return
        elif choice == 'a':
            keys_to_delete = keys
        else:
            try:
                idx = int(choice) - 1
                if idx < 0 or idx >= len(keys):
                    raise ValueError()
                keys_to_delete = [keys[idx]]
            except ValueError:
                logger.error("Invalid selection.")
                exit(1)

    for k in keys_to_delete:
        del_response = requests.delete(f"{SIGN_URL}/api/ssh-key/{k['id']}", headers=headers)
        if del_response.status_code == 200:
            logger.info(f"Key {k['id']} removed successfully.")
        else:
            logger.error(f"Failed to remove key {k['id']}: {del_response.status_code} - {del_response.text}")


def add_ssh_key(ssh_key_file):
     """
     Add an SSH key to the server.
                                                                                                                                                                 
     Args:
         ssh_key_file (file): The SSH key file to be added.
     """ 
     global token                                                                                                                                                        
     
     if not token:                                                                                                                                               
         raise EnvironmentError("TOKEN environment variable is not set")
                                                                                                                                                                 
     headers = {
         'Authorization': f'Bearer {token}',
         'Content-Type': 'application/json'
     }                                                                                                                                                           
                                                                                                                                                                 
     ssh_key = ssh_key_file.read().decode('utf-8')                                                                                                               
     payload = {                                                                                                                                                 
         'description': 'Added via gatehouse CLI tool',                                                                                                                      
         'key': ssh_key                                                                                                                                          
     }                                                                                                                                                           
                                                                                                                                                                 
     response = requests.post(f"{SIGN_URL}/api/ssh-key/add", json=payload, headers=headers)

     if response.status_code == 200:              
         ssh_key_id=response.json()['key_id']
         logger.info(f"SSH key {ssh_key_id} added successfully")
         generate_and_sign_challenge(ssh_key_file.name,ssh_key_id)
     else:                                                                                                                                                       
         logger.error(f"Failed to add SSH key: {response.status_code} - {response.text}")

def checkCert():
    logger.info("Running cert check")
    if not os.path.isfile(CERT_FILE_PATH):
        logger.warning("Certificate does not exist, new certificate required")
        return 1

    # Check the current cert first
    certificate = SSHCertificate.from_file(CERT_FILE_PATH)
    
    # Get the current datetime
    now = datetime.datetime.now()
    logger.debug(certificate
                 )
    
    # Check if the date is in the past or future
    if certificate.get("valid_before") > now:
        # Expiry is in the future
        if args.force:
            return 0
        else:
            logger.info("You have a valid SSH Certificate with the principals {} expiring at {}, not renewing. Use -f to force renewal".format(certificate.get("principals"), certificate.get("valid_before")))
            return 0
    else:
        logger.warning("Certificate is not valid, renewal required")
        return 1

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Sign an SSH key via a web service')
    parser.add_argument("-k", "--ssh-key", type=argparse.FileType('rb'), dest="sshkeyfile", help="Add an SSH Public Key to your user profile in gatehouse")
    parser.add_argument("-f", "--force", action='store_true', default=False, help="Force the certificate renewal")                                              
    parser.add_argument("-a", "--add-key", action='store_true', default=False, help="Add SSH key to the server")                                                
    parser.add_argument("-c", "--check-cert", action='store_true', default=False, help="Check the certificate, if it's valid exit 0, if it's invalid exit 1")
    parser.add_argument("-r", "--request-cert", action='store_true', default=False, help="Request that gatehouse sign a new certificate for you based on an SSH public key on file in your profile")
    parser.add_argument("--clear-cache", action='store_true', default=False, help="Remove the cached authentication token")
    parser.add_argument("--remove-key", nargs='?', const='', metavar='KEY_ID', help="Remove an SSH key from your profile. Omit KEY_ID to pick interactively.")

    args = parser.parse_args()
    # Ensure that one of --check-cert, --request-cert, or --add-key is provided
    if not (args.check_cert or args.request_cert or args.add_key or args.clear_cache or args.remove_key is not None):
        parser.error("At least one of --check-cert, --request-cert, --add-key, --validate-key, or --clear-cache must be provided.")
    

    # Retrieve SSH key from environment variables if not provided via CLI
    ssh_key_file = args.sshkeyfile if args.sshkeyfile else os.getenv('SSH_KEY_FILE')

    if args.check_cert:
        logger.info("Only checking certificate")
        exit(checkCert())

    if args.clear_cache:
        clear_token_cache()
        exit(0)

    if args.remove_key is not None:
        request_token()
        remove_ssh_key(args.remove_key if args.remove_key else None)
        exit(0)

    if args.add_key:
        request_token()
                                                                                                                                          
        if not ssh_key_file:
            logger.error("SSH key file is required to add SSH key")
            exit(1)

        # If ssh_key_file is retrieved from the environment, it will be a string (file path), so open it
        if isinstance(ssh_key_file, str):
            with open(ssh_key_file, 'rb') as f:
                ssh_key_file = f.read()

        add_ssh_key(ssh_key_file)                                                                                                              
        exit(0)                                                                                                                                                 


    if args.request_cert:                                                                                                                                                                    
        if args.force:
            request_token()
            logger.info("Forcing renewal of certificate")
            request_certificate()
        
        if checkCert() == 1:
            request_token()
            request_certificate()
    
        exit(0)
