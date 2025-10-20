import requests
import json
from cryptography.fernet import Fernet
from urllib.parse import unquote
from datetime import datetime, timedelta

class brownieGate:
    """
    brownieGate API Client
    
    This class provides secure communication between your application and 
    a remote API that uses encrypted payloads and verification tokens.
    
    Attributes:
        api_key (str): The API key for authenticating requests.
        project_uuid (str): The unique project identifier used by the API.
        encryption_key (str): The symmetric key for encrypting/decrypting payloads.
        base_url (str): The base URL for the API endpoint.
        base_headers (dict): Default headers used in all requests.
    """

    def __init__(self, api_key: str, project_uuid: str, encryption_key: str, url: str = 'http://your-api-url.com'):
        """
        Initialize the brownieGate client with credentials and connection info.

        Args:
            api_key (str): API key provided by the service.
            project_uuid (str): UUID identifying your project.
            encryption_key (str): Encryption key used for Fernet encryption/decryption.
            url (str, optional): Base URL of the API (default: 'http://your-api-url.com')
        """
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
        Verify a decrypted payload by checking its timestamp and validating with the API.

        Args:
            decrypted_payload (dict): The JSON payload obtained after decryption.

        Returns:
            tuple: (bool, str) - whether the payload is valid and the users ID.
        """
        token_time = datetime.fromisoformat(decrypted_payload.get('timestamp'))
        now = datetime.now()

        if token_time > now + timedelta(minutes=1):
            return False, 'Code is out of date'
        if token_time < now - timedelta(minutes=1):
            return False, 'Code is out of date'

        validate_url = f'{self.base_url}/api/validate'
        response = requests.post(validate_url, headers=self.base_headers, params={
            'code': decrypted_payload.get('code'),
        })

        if response.status_code == 200:
            result = response.json()
            if result.get('validated'):
                return True, result.get('user_id')
            else:
                return False
        else:
            raise Exception('Error contacting API.')
        
    def get_user_data(self, required_data: dict):
        """sumary_line
        
        Keyword arguments:
        argument -- description
        Return: return_description
        """
        validate_url = f'{self.base_url}/api/get_user_data'
        response = requests.post(validate_url, headers=self.base_headers, params={
            'required_data': required_data,
        })