# libpycognito

libpycognito demonstrates <b>Amazon Cognito</b> using Python.

Amazon Cognito lets you add user sign-up, sign-in, and access control to your web and mobile apps quickly and easily. 
Amazon Cognito scales to millions of users and supports sign-in with social identity providers, 
such as Facebook, Google, and Amazon, and enterprise identity providers via SAML 2.0.

The sample application is just a console application. Need to integrate to Flask to make it a browser application.
That part should be quite easy since it is just UI.


### Features:

        user
	1. signup (will receive email containing confirmation code)
	2. confirm signup (use confirmation code)
	3. forgot password (will receive email containing confirmation code)
	4. config forgot password (use confirmation code)
	5. login (will return access token)
	6. get user profile (use access token)
	7. update profile (use access token)
	8. change password (use access token)
	9. verify access token which is to be passed for succeeding api calls
	10. logout

	admin
	1. list users
	2. disable user
	3. enable user
	4. list groups for user
	5. add user to group (users who upgraded from free-tier can be transferred to subscription-tier group)
	6. remove user from group


### Instructions:

    1. Setup Amazon Cognito account
       A. Click on "Manage User Pools"
       B. Click on "Create a user pool"
       C. Type Pool name and click "Step through settings"
       D. Check "family name" and "given name" and click "Next step"
       E. Click "Next step"
       F. Click "Next step"
       G. Click "Next step"
       H. Click "Next step"
       I. Click "Next step"
       J. Click "Add an app client", type App client name, uncheck "Generate client secret", 
          click "Create app client" and click "Next step"
       K. Click "Next step"
       L. Click "Create pool"
       
    2. Update 
       A. CONFIG_USER_POOL_REGION = Region of Cognito User Pool ex. "ap-southeast-1"
       B. CONFIG_USER_POOL_ID     = Copy from General settings/Pool Id
       C. CONFIG_CLIENT_ID        = Copy from General settings/App clients/App client id
    
    3. Install Python libraries
       pip install -r requirements.txt
    

### References:

https://docs.aws.amazon.com/cognito/latest/developerguide/what-is-amazon-cognito.html
https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-idp.html
https://github.com/capless/warrant

