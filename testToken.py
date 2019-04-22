#!python

import requests, argparse

parser = argparse.ArgumentParser()
parser.add_argument('-u', dest='userName', help='user name to auth')
parser.add_argument('-p', dest='passWord', help='password to auth')
parser.add_argument('-tu', dest='oamTokenUser', help='oam token user')
parser.add_argument('-tp', dest='oamTokenPass', help='oam token password')
parser.add_argument('-vu', dest='oamValidatorUser', help='oam validator user')
parser.add_argument('-vp', dest='oamValidatorPass', help='oam validator password')
args = parser.parse_args()

oamUrl = 'https://oam.ppd.veloe.com.br'
userName = args['userName']
passWord = args['passWord']

oamTokenUser = args['oamTokenUser']
oamTokenPass = args['oamTokenPass']

oamValidatorUser = args['oamValidatorUser']
oamValidatorPass = args['oamValidatorPass']

getTokenRequest = {
	'grant_type': 'password',
	'username': userName,
	'password': passWord,
	'scope': 'primeiro-acesso.insert.credenciais'
}
token = requests.post(oamUrl + '/ms_oauth/oauth2/endpoints/oauthservice/tokens', data=getTokenRequest, auth=(oamTokenUser, oamTokenPass), verify=False)
print(token.text)

validateRequest = {
	'grant_type': 'oracle-idm%3A%2Foauth%2Fgrant-type%2Fresource-access-token%2Fjwt',
	'oracle_token_action': 'validate',
	'scope': 'primeiro-acesso.insert.credenciais',
	'assertion': token.text
}
resultValidator = requests.post(oamUrl + '/ms_oauth/oauth2/endpoints/oauthservice/tokens', data=validateRequest, auth=(oamValidatorUser, oamValidatorPass), verify=False)

print(resultValidator.text)