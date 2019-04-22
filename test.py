#!python

import requests

oamUrl = 'https://oam.ppd.veloe.com.br'
userName = '27729523809'
passWord = 'veloe1010'

oamTokenUser = 'SistemaPrimeiroAcesso'
oamTokenPass = 'Iq60Ci6VEqQ7Hjs'

oamValidatorUser = 'ServiceTokenValidator'
oamValidatorPass = 'MKnATbMlgeVqBnXH'

getTokenRequest = {
	'grant_type': 'password',
	'username': userName,
	'password': passWord,
	'scope': 'primeiro-acesso.insert.credenciais'
}
token = requests.post(oamUrl + '/ms_oauth/oauth2/endpoints/oauthservice/tokens', data=getTokenRequest, auth=(oamTokenUser, oamTokenPass))

validateRequest = 'grant_type=oracle-idm%3A%2Foauth%2Fgrant-type%2Fresource-access-token%2Fjwt&oracle_token_action=validate&scope=primeiro-acesso.insert.credenciais&assertion=' + token
resultValidator = requests.post(oamUrl + '/ms_oauth/oauth2/endpoints/oauthservice/tokens', data=validateRequest, auth=(oamValidatorUser, oamValidatorPass))
