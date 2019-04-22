#!python

import requests, argparse, json

parser = argparse.ArgumentParser()
parser.add_argument('-u', dest='userName', help='user name to auth', required=True)
parser.add_argument('-p', dest='passWord', help='password to auth', required=True)
parser.add_argument('-tu', dest='oamTokenUser', help='oam token user', required=True)
parser.add_argument('-tp', dest='oamTokenPass', help='oam token password', required=True)
parser.add_argument('-vu', dest='oamValidatorUser', help='oam validator user', required=True)
parser.add_argument('-vp', dest='oamValidatorPass', help='oam validator password', required=True)
args = parser.parse_args()

oamUrl = 'https://oam.ppd.veloe.com.br'

getTokenRequest = {
	'grant_type': 'password',
	'username': args.userName,
	'password': args.passWord,
	'scope': 'primeiro-acesso.insert.credenciais'
}
token = requests.post(oamUrl + '/ms_oauth/oauth2/endpoints/oauthservice/tokens', data=getTokenRequest, auth=(args.oamTokenUser, args.oamTokenPass), verify=False)
# print(json.loads(token.text)['access_token'])

validateRequest = {
	'grant_type': 'oracle-idm:/oauth/grant-type/resource-access-token/jwt',
	'oracle_token_action': 'validate',
	'scope': 'primeiro-acesso.insert.credenciais',
	'assertion': json.loads(token.text)['access_token']
}

count = 0
while count < 100:
	resultValidator = requests.post(oamUrl + '/ms_oauth/oauth2/endpoints/oauthservice/tokens', data=validateRequest, auth=(args.oamValidatorUser, args.oamValidatorPass), verify=False)
	print(resultValidator.text)
	count += 1

