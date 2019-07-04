# libpycognito

libpycognito demonstrates Amazon Cognito using Python.

Amazon Cognito lets you add user sign-up, sign-in, and access control to your web and mobile apps quickly and easily. 
Amazon Cognito scales to millions of users and supports sign-in with social identity providers, 
such as Facebook, Google, and Amazon, and enterprise identity providers via SAML 2.0.


### Flow:

	1. signup (will receive email containing confirmation code)
	2. confirm signup (use confirmation code)
	3. login, logout
	4. update profile
	5. initiate forgot password (will receive email containing confirmation code)
	6. confirm forgot password (use confirmation code)
	7. login_ex (returns access token with id token and refresh token)
	8. verify access token which is to be passed for succeeding api calls


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
       
    2. Update cognito_config.py
	      A. CONFIG_USER_POOL_REGION = Region of Cognito User Pool ex. "ap-southeast-1"
	      B. CONFIG_USER_POOL_ID     = Copy from General settings/Pool Id
	      C. CONFIG_CLIENT_ID        = Copy from General settings/App clients/App client id
    
    3. Install Python libraries
       pip install -r requirements.txt
    

### References:

https://docs.aws.amazon.com/cognito/latest/developerguide/what-is-amazon-cognito.html
https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-idp.html
https://github.com/capless/warrant

