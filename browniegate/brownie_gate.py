import requests
import json
from cryptography.fernet import Fernet
from urllib.parse import unquote
from datetime import datetime, timedelta
import ast


class brownieGate:
    """
    brownieGate API Client
    
    This class provides a secure interface between your application and a 
    remote API that uses encrypted payloads and verification tokens. It 
    handles encryption, decryption, validation, and cookie management.
    
    Attributes:
        api_key (str): The API key for authenticating requests.
        project_uuid (str): The unique project identifier used by the API.
        encryption_key (str): The symmetric key for encrypting/decrypting payloads.
        base_url (str): The base URL for the API endpoint.
        base_headers (dict): Default headers used in all requests.
        debug (bool): If True, prints debug messages during requests.
    """

    def __init__(self, api_key: str, project_uuid: str, encryption_key: str, url: str = 'https://www.browniegate.xyz/', debug: bool = False):
        """
        Initialize the brownieGate client with credentials and connection info.

        Args:
            api_key (str): API key provided by the service.
            project_uuid (str): UUID identifying your project.
            encryption_key (str): Encryption key used for Fernet encryption/decryption.
            url (str): Base URL of the API.
            debug (bool, optional): If True, enables debug logging. Defaults to False.
        """
        self.debug = debug
        self.api_key = api_key
        self.project_uuid = project_uuid
        self.encryption_key = encryption_key
        self.base_url = url.rstrip('/')
        self.base_headers = {
            'authorization': self.api_key,
            'project-uuid': self.project_uuid,
            'Content-Type': 'application/json',
        }

    def decrypt_payload(self, payload: str):
        """
        Decrypt an encrypted payload using Fernet symmetric encryption.

        Args:
            payload (str): The encrypted and URL-encoded payload string.

        Returns:
            dict: The decrypted and parsed JSON payload.

        Raises:
            Exception: If the payload cannot be decrypted or parsed.
        """
        try:
            fernet = Fernet(self.encryption_key.encode())
            payload = unquote(payload)
            decrypted = fernet.decrypt(payload.encode()).decode()
            return json.loads(decrypted)
        except Exception as e:
            raise Exception(e)

    def verify_payload(self, decrypted_payload: dict):
        """
        Verify a decrypted payload by checking its timestamp and validating it with the API.

        Args:
            decrypted_payload (dict): The JSON payload obtained after decryption.

        Returns:
            tuple: (bool, str)
                - bool: Whether the payload is valid.
                - str: The user's ID if valid, otherwise an empty string.

        Raises:
            Exception: If communication with the API fails.
        """
        token_time = datetime.fromisoformat(decrypted_payload.get('timestamp'))
        now = datetime.now()

        if token_time > now + timedelta(minutes=1):
            return False, ''
        if token_time < now - timedelta(minutes=1):
            return False, ''
        
        if self.debug:
            print('Pinging validate user')

        url = f'{self.base_url}/api/user/validate'
        response = requests.post(url, headers=self.base_headers, params={
            'code': decrypted_payload.get('code'),
        })

        if response.status_code == 200:
            result = response.json()
            if result.get('validated'):
                return True, result.get('user_id')
            else:
                return False, ''
        else:
            raise Exception('Failed to contact API.')

    def get_user_data(self, user_id: str):
        """
        Retrieve user data from the API.

        Args:
            user_id (str): The ID of the user to retrieve.

        Returns:
            tuple: (bool, dict)
                - bool: Whether the request succeeded.
                - dict: The user's data if successful, otherwise an empty string.

        Raises:
            Exception: If communication with the API fails.
        """
        try:
            if self.debug:
                print('Pinging get user data')
            url = f'{self.base_url}/api/user/get_data'
            response = requests.post(url, headers=self.base_headers, params={
                'user_id': user_id
            })
            
            if response.status_code == 200:
                result = response.json()
                if result.get('validated'):
                    result.pop('validated')
                    return True, result
                else:
                    return False, ''
            else:
                raise Exception('Failed to contact API.')
        except Exception as e:
            raise Exception(str(e))

    def generate_cookie(self, user_id: str):
        """
        Request a secure cookie from the API for a given user and encrypt it.

        Args:
            user_id (str): The ID of the user for whom to generate the cookie.

        Returns:
            bytes: The encrypted cookie, or None if unsuccessful.

        Raises:
            Exception: If communication with the API fails.
        """
        try:
            if self.debug:
                print('Pinging generate cookie')
            url = f'{self.base_url}/api/cookie/generate'
            response = requests.post(url, headers=self.base_headers, params={
                'user_id': user_id
            })
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    fernet = Fernet(self.encryption_key.encode())
                    cookie = fernet.encrypt(result.get('cookie').encode())
                    return cookie
                else:
                    return None
            else:
                raise Exception('Failed to contact API.')
        except Exception as e:
            raise Exception(str(e))

    def decrypt_cookie(self, cookie: str):
        """
        Decrypt an encrypted cookie and extract the stored data.

        Args:
            cookie (str): The encrypted cookie.

        Returns:
            tuple: (str, str)
                - str: The user ID.
                - str: The cookie hash.

        Raises:
            Exception: If decryption fails or data is invalid.
        """
        try:
            fernet = Fernet(self.encryption_key.encode())
            data = ast.literal_eval(fernet.decrypt(cookie).decode())
            return data.get('user_id'), data.get('hash')
        except Exception as e:
            raise Exception(str(e))

    def validate_cookie(self, user_id: str, cookie_hash: str):
        """
        Validate a user's cookie with the API.

        Args:
            user_id (str): The user ID associated with the cookie.
            cookie_hash (str): The hash value of the cookie to validate.

        Returns:
            bool: True if the cookie is valid, False otherwise.

        Raises:
            Exception: If communication with the API fails.
        """
        try:
            if self.debug:
                print('Pinging validating cookie')
            url = f'{self.base_url}/api/cookie/validate'
            response = requests.post(url, headers=self.base_headers, params={
                'user_id': user_id,
                'cookie_hash': cookie_hash
            })
            
            if response.status_code == 200:
                result = response.json()
                return bool(result.get('success'))
            else:
                raise Exception('Failed to contact API.')
        except Exception as e:
            raise Exception(str(e))

    def remove_cookie(self, user_id: str):
        """
        Remove an active cookie for a specific user.

        Args:
            user_id (str): The ID of the user whose cookie should be removed.

        Raises:
            Exception: If communication with the API fails.
        """
        try:
            if self.debug:
                print('Pinging remove cookie')
            url = f'{self.base_url}/api/cookie/remove'
            response = requests.post(url, headers=self.base_headers, params={
                'user_id': user_id
            })
            
            if response.status_code != 200:
                raise Exception('Failed to contact API.')
        except Exception as e:
            raise Exception(str(e))

    def get_pfp(self, user_id: str):
        """
        Retrieve a user's profile picture URL from the API.

        Args:
            user_id (str): The ID of the user.

        Returns:
            str | bool: The profile picture URL if found, otherwise False.

        Raises:
            Exception: If communication with the API fails.
        """
        try:
            if self.debug:
                print('Pinging get user pfp')
            url = f'{self.base_url}/api/user/get_pfp'
            response = requests.post(url, headers=self.base_headers, params={
                'user_id': user_id
            })
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    return result.get('pfp')
                else:
                    return False
            else:
                raise Exception('Failed to contact API.')
        except Exception as e:
            raise Exception(str(e))