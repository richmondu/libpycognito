from cognito_client import CognitoClient
import argparse
import sys



#####################################################################
# Note: Don't forget to set Cognito configuration cognito_config.py
# This should match with the Cognito setup in AWS Cognito dashboard
#####################################################################



#####################################################################
#
# Demonstrate Amazon Cognito in console
#
# 1. signup
# 2. confirm signup
# 3. login, logout
# 4. update profile
# 5. initiate forgot password
# 6. confirm forgot password
# 7. login_ex (returns access token with id token and refresh token)
# 8. verify access token which is to be passed for succeeding api calls
#
#####################################################################
def main(args):

	#################################################################
	# init
	#################################################################
	email       = 'richmond.umagat@yahoo.com'
	username    = 'richmondu'
	password    = 'P@$$w0rd'
	first_name  = 'Richi'
	family_name = 'Umagat'
	cg = CognitoClient()

	#################################################################
	# signup
	# Note: check email for the confirmation code
	#################################################################
	if False:
		cg.signup(email, username, password, first_name, family_name)

	#################################################################
	# confirm signup
	# Note: verify if new user appears in the Users Pool
	#################################################################
	if False:
		confirmation_code = '526558'
		cg.confirm_signup(username, confirmation_code)

	#################################################################
	# login/logout
	#################################################################
	if False:
		try:
			(client, tokens) = cg.login(username, password)
			user = cg.get_user_details(client, username)
			print(user)
			cg.logout(client)
			pass
		except:
			print("incorrect username or password")

	#################################################################
	# update profile
	#################################################################
	if False:
		try:
			(client, tokens) = cg.login(username, password)
			user = cg.get_user_details(client, username)
			print(user)
			first_name  = 'Richie'
			family_name = 'Umagat'
			cg.update_profile(client, first_name, family_name)
			cg.logout(client)
			pass
		except:
			print("incorrect username or password")

	#################################################################
	# initiate forgot password
	#################################################################
	if False:
		cg.initiate_forgot_password(username)

	#################################################################
	# confirm forgot password
	#################################################################
	new_password = 'P@$$w0rd'
	if False:
		confirmation_code = '385641'
		cg.confirm_forgot_password(username, confirmation_code, new_password)
		password = new_password

	#################################################################
	# login to test new password
	#################################################################
	if False:
		try:
			(client, tokens) = cg.login(username, password)
			cg.logout(client)
		except:
			print("incorrect username or password")



	#################################################################
	# login using SRP
	#################################################################
	if True:
		try:
			(client, tokens) = cg.login_ex(username, password)
			print("login successful")

			id_token = tokens['AuthenticationResult']['IdToken']
			refresh_token = tokens['AuthenticationResult']['RefreshToken']
			access_token = tokens['AuthenticationResult']['AccessToken']
			print("AccessToken:  \r\n{}\r\n".format(access_token))

			keys = cg.get_userpool_keys()
			valid = cg.is_token_valid(username, access_token, keys)
			print("token is {}!".format("valid" if valid else "invalid"))
		except:
			print("incorrect username or password")


def parse_arguments(argv):

	parser = argparse.ArgumentParser()
	return parser.parse_args(argv)


if __name__ == '__main__':
	main(parse_arguments(sys.argv[1:]))

