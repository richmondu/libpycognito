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
# 1. signup (will receive email containing confirmation code)
# 2. confirm signup (use confirmation code)
# 3. forgot password (will receive email containing confirmation code)
# 4. config forgot password (use confirmation code)
# 5. login (will return access token)
# 6. get user profile (use access token)
# 7. update profile (use access token)
# 8. change password (use access token)
# 9. verify access token which is to be passed for succeeding api calls
#
#####################################################################
def main(args):

	#################################################################
	# init
	#################################################################
	email       = 'richmond.umagat@yahoo.com'
	username    = 'richmondu'
	password    = 'P@$$w0rd'
	first_name  = 'Lebron'
	last_name   = 'James'
	cg = CognitoClient()



	#################################################################
	# sign_up
	# Note: check email for the confirmation code
	#################################################################
	if False:
		print("\r\nsign_up")
		(result, response) = cg.sign_up(username, password, email=email, given_name=first_name, family_name=last_name)
		print(result)

	#################################################################
	# confirm sign_up
	# Note: use confirmation code from email
	# Note: verify if new user appears in the Users Pool
	#################################################################
	if False:
		print("\r\nconfirm_sign_up")
		confirmation_code = '237956'
		(result, response) = cg.confirm_sign_up(username, confirmation_code)
		print(result)



	#################################################################
	# forgot password
	# Note: check email for the confirmation code
	#################################################################
	if False:
		print("\r\nforgot_password")
		(result, response) = cg.forgot_password(username)
		print(result)

	#################################################################
	# confirm forgot password
	# Note: use confirmation code from email
	#################################################################
	if False:
		print("\r\nconfirm_forgot_password")
		new_password = 'P@$$w0rd'
		confirmation_code = '847689'
		(result, response) = cg.confirm_forgot_password(username, confirmation_code, new_password)
		print(result)
		password = new_password



	#################################################################
	# login
	#################################################################
	if True:
		print("\r\nlogin")
		(result, response, client) = cg.login(username, password)
		print(result)
		if not result:
			return
		access_token = response['AuthenticationResult']['AccessToken']
		print(access_token)

		#################################################################
		# get user profile
		#################################################################
		if True:
			print("\r\nget_user")
			(result, user_attributes) = cg.get_user(access_token)
			print(result)
			print(user_attributes)

		#################################################################
		# update user profile
		#################################################################
		if True:
			print("\r\nupdate_user")
			first_name = "Lebron"
			last_name  = "James"
			(result, response) = cg.update_user(access_token, email=email, given_name=first_name, family_name=last_name)
			print(result)
			(result, user_attributes) = cg.get_user(access_token)
			print(result)
			print(user_attributes)

		#################################################################
		# change user password
		#################################################################
		if True:
			print("\r\nchange_password")
			new_password = 'P@$$w0rd'
			(result, response) = cg.change_password(access_token, password, new_password)
			if not result and password == new_password:
				result = True
			print(result)

		#################################################################
		# verify token
		#################################################################
		if True:
			print("\r\nverify_token")
			valid = cg.verify_token(access_token, username)
			print("token is {}!".format("valid" if valid else "invalid"))



def parse_arguments(argv):

	parser = argparse.ArgumentParser()
	return parser.parse_args(argv)


if __name__ == '__main__':
	main(parse_arguments(sys.argv[1:]))

