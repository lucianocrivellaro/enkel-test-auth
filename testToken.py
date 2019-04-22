#!python

import requests, argparse, json

parser = argparse.ArgumentParser()
parser.add_argument('-url', dest='oamUrl', help='URL do OAM', required=True)
parser.add_argument('-urlValidator', dest='oamUrlVal', help='URL do OAM', required=False)
parser.add_argument('-u', dest='userName', help='user name to auth', required=True)
parser.add_argument('-p', dest='passWord', help='password to auth', required=True)
parser.add_argument('-tu', dest='oamTokenUser', help='oam token user', required=True)
parser.add_argument('-tp', dest='oamTokenPass', help='oam token password', required=True)
parser.add_argument('-vu', dest='oamValidatorUser', help='oam validator user', required=True)
parser.add_argument('-vp', dest='oamValidatorPass', help='oam validator password', required=True)
args = parser.parse_args()

getTokenRequest = {
    'grant_type': 'password',
    'username': args.userName,
    'password': args.passWord,
    'scope': 'primeiro-acesso.insert.credenciais'
}
try:
    print('Pegando o token de acesso')
    token = requests.post('https://' + args.oamUrl + '/ms_oauth/oauth2/endpoints/oauthservice/tokens', data=getTokenRequest, auth=(args.oamTokenUser, args.oamTokenPass), verify=False)
    pass
except Exception as e:
    raise e
print('Token recebido')
# print(json.loads(token.text)['access_token'])

validateRequest = {
    'grant_type': 'oracle-idm:/oauth/grant-type/resource-access-token/jwt',
    'oracle_token_action': 'validate',
    'scope': 'primeiro-acesso.insert.credenciais',
    'assertion': json.loads(token.text)['access_token']
}

print('Fazendo 100 chamadas de validação...')

if 'oamUrlVal' not in args:
    urlValidator = args.oamUrl
else:
    urlValidator = args.oamUrlVal
count = 0
while count < 100:
    try:
        resultValidator = requests.post('https://' + urlValidator + '/ms_oauth/oauth2/endpoints/oauthservice/tokens', data=validateRequest, auth=(args.oamValidatorUser, args.oamValidatorPass), verify=False)
        print(resultValidator.text)
        pass
    except Exception as e:
        raise e
    count += 1

