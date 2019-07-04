# libpycognito

libpycognito demonstrates using Amazon Cognito using Python.


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



