from cognito_client import CognitoClient
import argparse
import sys



#####################################################################
# Note: Don't forget to set Cognito configuration cognito_config.py
# This should match with the Cognito setup in AWS Cognito dashboard
#####################################################################



def test_user():

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
		(result, response) = cg.login(username, password)
		print(result)
		if not result:
			return
		access_token = response['AuthenticationResult']['AccessToken']
		refresh_token = response['AuthenticationResult']['RefreshToken']
		id_token = response['AuthenticationResult']['IdToken']
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

		#################################################################
		# logout
		#################################################################
		if True:
			print("\r\nlogout")
			(result, response) = cg.logout(access_token)
			print(result)


def test_admin():

	#################################################################
	email       = 'richmond.umagat@yahoo.com'
	username    = 'admin'
	password    = 'P@$$w0rd'
	first_name  = 'admin'
	last_name   = 'admin'
	cg = CognitoClient()


	#################################################################
	# login
	#################################################################
	if True:
		print("\r\nlogin")
		(result, response) = cg.login(username, password)
		print(result)
		if not result:
			return
		access_token = response['AuthenticationResult']['AccessToken']
		refresh_token = response['AuthenticationResult']['RefreshToken']
		id_token = response['AuthenticationResult']['IdToken']
		print(access_token)


		#################################################################
		# list users
		#################################################################
		if True:
			print("\r\nadmin_list_users")
			(result, users) = cg.admin_list_users()
			print(result)
			print(len(users))
			cg.admin_display_users(users)


		#################################################################
		# disable user
		#################################################################
		if True:
			print("\r\nadmin_disable_user")
			username = "richmondu"
			(result, users) = cg.admin_disable_user(username)
			print(result)

			(result, users) = cg.admin_list_users()
			cg.admin_display_users(users)


		#################################################################
		# enable user
		#################################################################
		if True:
			print("\r\nadmin_enable_user")
			username = "richmondu"
			(result, users) = cg.admin_enable_user(username)
			print(result)

			(result, users) = cg.admin_list_users()
			cg.admin_display_users(users)


		#################################################################
		# list groups for user
		#################################################################
		if True:
			print("\r\nadmin_list_groups_for_user")
			username = "richmondu"
			(result, groups) = cg.admin_list_groups_for_user(username)
			print(result)
			cg.admin_display_groups_for_user(groups)


		#################################################################
		# add user to group
		#################################################################
		if True:
			print("\r\nadmin_add_user_to_group")
			username = "richmondu"
			groupname = "PaidUsersGroup"
			(result, response) = cg.admin_add_user_to_group(username, groupname)
			print(result)

			(result, groups) = cg.admin_list_groups_for_user(username)
			cg.admin_display_groups_for_user(groups)


		#################################################################
		# remove user from group
		#################################################################
		if True:
			print("\r\nadmin_remove_user_from_group")
			username = "richmondu"
			groupname = "PaidUsersGroup"
			(result, response) = cg.admin_remove_user_from_group(username, groupname)
			print(result)

			(result, groups) = cg.admin_list_groups_for_user(username)
			cg.admin_display_groups_for_user(groups)


		#################################################################
		# logout user
		#################################################################
		if True:
			print("\r\nadmin_logout_user")
			username = "richmondu"
			(result, response) = cg.admin_logout_user(username)
			print(result)


		#################################################################
		# delete user
		#################################################################
		if True:
			print("\r\nadmin_delete_user")
			username = "richmondu"
			(result, response) = cg.admin_delete_user(username)
			print(result)



#####################################################################
#
# Demonstrate Amazon Cognito in console
#
# test_user
# 1. signup (will receive email containing confirmation code)
# 2. confirm signup (use confirmation code)
# 3. forgot password (will receive email containing confirmation code)
# 4. config forgot password (use confirmation code)
# 5. login (will return access token)
# 6. get user profile (use access token)
# 7. update profile (use access token)
# 8. change password (use access token)
# 9. verify access token which is to be passed for succeeding api calls
# 10. logout
#
# test_admin
# 1. list users
# 2. disable user
# 3. enable user
# 4. list groups for user
# 5. add user to group (users who upgraded from free-tier can be transferred to subscription-tier group)
# 6. remove user from group
# 7. logout a user
# 8. delete user
#
#####################################################################
def main(args):

	#test_user()
	test_admin()


def parse_arguments(argv):

	parser = argparse.ArgumentParser()
	return parser.parse_args(argv)


if __name__ == '__main__':
	main(parse_arguments(sys.argv[1:]))

