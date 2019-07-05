import boto3
from warrant.aws_srp import AWSSRP
from cognito_config import config
import time
import ast



class CognitoClient:

	def __init__(self):
		self.client_id   = config.CONFIG_CLIENT_ID
		self.pool_id     = config.CONFIG_USER_POOL_ID
		self.pool_region = config.CONFIG_USER_POOL_REGION
		self.keys        = None
		self.keys_iss    = None

	def __get_userpool_keys(self):
		import urllib.request
		import json
		keys_iss = 'https://cognito-idp.{}.amazonaws.com/{}'.format(config.CONFIG_USER_POOL_REGION, config.CONFIG_USER_POOL_ID)
		keys_url = '{}/.well-known/jwks.json'.format(keys_iss)
		response = urllib.request.urlopen(keys_url)
		keys = json.loads(response.read())['keys']
		return keys, keys_iss

	def __get_client(self):
		return boto3.Session(region_name=self.pool_region).client('cognito-idp')

	def __dict_to_cognito(self, attributes, attr_map=None):
		if attr_map is None:
			attr_map = {}
		for k,v in attr_map.items():
			if v in attributes.keys():
				attributes[k] = attributes.pop(v)
		return [{'Name': key, 'Value': value} for key, value in attributes.items()]

	def __cognito_to_dict(self, attr_list, attr_map=None):
		if attr_map is None:
			attr_map = {}
		attr_dict = dict()
		for a in attr_list:
			name = a.get('Name')
			value = a.get('Value')
			if value in ['true', 'false']:
				value = ast.literal_eval(value.capitalize())
			name = attr_map.get(name,name)
			attr_dict[name] = value
		return attr_dict

	def __get_result(self, response):
		return True if response["ResponseMetadata"]["HTTPStatusCode"] == 200 else False



	def sign_up(self, username, password, **attributes):
		params = {
			'ClientId'       : self.client_id,
			'Username'       : username,
			'Password'       : password,
			'UserAttributes' : self.__dict_to_cognito(attributes)
		}
		try:
			response = self.__get_client().sign_up(**params)
		except:
			return (False, None)
		return (self.__get_result(response), response)

	def confirm_sign_up(self, username, confirmation_code):
		params = {
			'ClientId'        : self.client_id,
			'Username'        : username,
			'ConfirmationCode': confirmation_code
		}
		try:
			response = self.__get_client().confirm_sign_up(**params)
		except:
			return (False, None)
		return (self.__get_result(response), response)



	def forgot_password(self, username):
		params = {
			'ClientId': self.client_id,
			'Username': username
		}
		try:
			response = self.__get_client().forgot_password(**params)
		except:
			return (False, None)
		return (self.__get_result(response), response)

	def confirm_forgot_password(self, username, confirmation_code, new_password):
		params = {
			'ClientId'        : self.client_id,
			'Username'        : username,
			'ConfirmationCode': confirmation_code,
			'Password'        : new_password
		}
		try:
			response = self.__get_client().confirm_forgot_password(**params)
		except:
			return (False, None)
		return (self.__get_result(response), response)





	def login(self, username, password):
		client = self.__get_client()
		params = {
			'username'  : username,
			'password'  : password,
			'pool_id'   : self.pool_id,
			'client_id' : self.client_id,
			'client'    : client
		}
		try:
			aws = AWSSRP(**params)
			response = aws.authenticate_user()
			(self.keys, self.keys_iss) = self.__get_userpool_keys()
		except:
			return (False, None, None)
		return (self.__get_result(response), response, client)

	def get_user(self, access_token):
		params = {
			'AccessToken': access_token
		}
		try:
			response = self.__get_client().get_user(**params)
			user_attributes = self.__cognito_to_dict(response["UserAttributes"])
			user_attributes.pop("sub")
			user_attributes.pop("email_verified")
		except:
			return (False, None)
		return (self.__get_result(response), user_attributes)

	def update_user(self, access_token, **attributes):
		params = {
			'AccessToken'    : access_token,
			'UserAttributes' : self.__dict_to_cognito(attributes)
		}
		try:
			response = self.__get_client().update_user_attributes(**params)
		except:
			return (False, None)
		return (self.__get_result(response), response)
	
	def change_password(self, access_token, password, new_password):
		params = {
			'PreviousPassword': password,
			'ProposedPassword': new_password,
			'AccessToken'     : access_token
		}
		try:
			response = self.__get_client().change_password(**params)
		except:
			return (False, None)
		return (self.__get_result(response), response)

	def verify_token(self, token, username):
		from jose import jwk, jwt
		from jose.utils import base64url_decode

		# get the kid from the headers prior to verification
		headers = jwt.get_unverified_header(token)
		kid = headers['kid']

		# search for the kid in the downloaded public keys
		key_index = -1
		for i in range(len(self.keys)):
			if kid == self.keys[i]['kid']:
				key_index = i
				break
		if key_index == -1:
			print('Public key not found in jwks.json')
			return False

		# construct the public key
		public_key = jwk.construct(self.keys[key_index])

		# get the last two sections of the token,
		# message and signature (encoded in base64)
		message, encoded_signature = str(token).rsplit('.', 1)

		# decode the signature
		decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))

		# verify the signature
		if not public_key.verify(message.encode("utf8"), decoded_signature):
			print('Signature verification failed')
			return False

		# since we passed the verification, we can now safely
		# use the unverified claims
		claims = jwt.get_unverified_claims(token)
		if claims["token_use"] != "access":
			print('Token is not an access token')
			return False
		curr_time = time.time()
		if curr_time > claims["exp"] or curr_time < claims["iat"]:
			print('Token is expired')
			return False
		if claims["client_id"] != config.CONFIG_CLIENT_ID:
			print('Token was not issued for this client_id')
			return False
		if claims["username"] != username:
			print('Token was not issued for this username')
			return False
		if claims['iss'] != self.keys_iss:
			print('Token was not issued for this pool_id')
			return False
		return True

	def logout(self, client):
		pass






