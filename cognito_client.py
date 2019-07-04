from warrant import Cognito
from cognito_config import config
import time



class CognitoClient:

	def __init__(self):
		pass

	def signup(self, email, username, password, first_name, family_name):
		client = Cognito(config.CONFIG_USER_POOL_ID, config.CONFIG_CLIENT_ID, user_pool_region=config.CONFIG_USER_POOL_REGION)
		client.add_base_attributes(email=email, given_name=first_name, family_name=family_name)
		response = client.register(username, password)
		print(response)

	def confirm_signup(self, username, confirmation_code):
		client = Cognito(config.CONFIG_USER_POOL_ID, config.CONFIG_CLIENT_ID, user_pool_region=config.CONFIG_USER_POOL_REGION)
		client.confirm_sign_up(confirmation_code, username=username)

	def login(self, username, password):
		client = Cognito(config.CONFIG_USER_POOL_ID, config.CONFIG_CLIENT_ID, user_pool_region=config.CONFIG_USER_POOL_REGION, username=username)
		client.authenticate(password=password)
		#client.admin_authenticate(password=password)
		return (client, None)

	def login_ex(self, username, password):
		import boto3
		from warrant.aws_srp import AWSSRP
		client = boto3.Session(region_name=config.CONFIG_USER_POOL_REGION).client('cognito-idp')
		aws = AWSSRP(username=username, password=password, pool_id=config.CONFIG_USER_POOL_ID, client_id=config.CONFIG_CLIENT_ID, client=client)
		tokens = aws.authenticate_user()
		return (client, tokens)

	def get_user_details(self, client, username):
	#	return client.get_user()
		return client.get_user_obj(username=username,
			attribute_list=[{'Name': 'string','Value': 'string'},],
			metadata={},
			attr_map={"given_name":"given_name","family_name":"family_name", }
			)

	def update_profile(self, client, first_name, family_name):
		client.update_profile({'given_name':first_name,'family_name':family_name, },attr_map=dict())

	def logout(self, client):
		client.logout()

	def initiate_forgot_password(self, username):
		client = Cognito(config.CONFIG_USER_POOL_ID, config.CONFIG_CLIENT_ID, user_pool_region=config.CONFIG_USER_POOL_REGION, username=username)
		client.initiate_forgot_password()

	def confirm_forgot_password(self, username, confirmation_code, new_password):
		client = Cognito(config.CONFIG_USER_POOL_ID, config.CONFIG_CLIENT_ID, user_pool_region=config.CONFIG_USER_POOL_REGION, username=username)
		client.confirm_forgot_password(confirmation_code, new_password)



	def get_userpool_keys(self):
		import urllib.request
		import json
		keys_url = 'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'.format(config.CONFIG_USER_POOL_REGION, config.CONFIG_USER_POOL_ID)
		response = urllib.request.urlopen(keys_url)
		keys = json.loads(response.read())['keys']
		return keys

	def is_token_valid(self, username, token, keys):
		from jose import jwk, jwt
		from jose.utils import base64url_decode

		# get the kid from the headers prior to verification
		headers = jwt.get_unverified_header(token)
		kid = headers['kid']

		# search for the kid in the downloaded public keys
		key_index = -1
		for i in range(len(keys)):
			if kid == keys[i]['kid']:
				key_index = i
				break
		if key_index == -1:
			print('Public key not found in jwks.json')
			return False

		# construct the public key
		public_key = jwk.construct(keys[key_index])

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
		return True
