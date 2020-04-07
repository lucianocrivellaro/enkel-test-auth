#!python

import requests, argparse, json, logging, time, sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning

logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class bitColors:
    HEADER = '\033[1;35m'
    OKBLUE = '\033[1;34m'
    OKGREEN = '\033[1;32m'
    WARNING = '\033[1;33m'
    FAIL = '\033[1;31m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def printSuccess(text2Print ):
    print ("\033[32;1m" + text2Print + "\033[0m")
def printWarning(text2Print ):
    print ("\033[33;1m" + text2Print + "\033[0m")
def printError(text2Print ):
    print ("\033[31;1m" + text2Print + "\033[0m")
def returnSuccess(text2Print ):
    return ("\033[32;1m" + text2Print + "\033[0m")
def returnWarning(text2Print ):
    return ("\033[33;1m" + text2Print + "\033[0m")
def returnError(text2Print ):
    return ("\033[31;1m" + text2Print + "\033[0m")


parser = argparse.ArgumentParser()
parser.add_argument('-url', dest='oamUrl', help='URL do OAM', required=True)
parser.add_argument('-urlValidator', dest='oamUrlVal', help='URL do OAM', required=False)
parser.add_argument('-u', dest='userName', help='user name to auth', required=True)
parser.add_argument('-p', dest='passWord', help='password to auth', required=True)
parser.add_argument('-tu', dest='oamTokenUser', help='oam token user', required=True)
parser.add_argument('-tp', dest='oamTokenPass', help='oam token password', required=True)
parser.add_argument('-vu', dest='oamValidatorUser', help='oam validator user', required=True)
parser.add_argument('-vp', dest='oamValidatorPass', help='oam validator password', required=True)
parser.add_argument('-i', dest='requestInterval', help='intervalo entre gerar o token e a primeira validacao em milisegundos', required=True, type=int)
args = parser.parse_args()

getTokenRequest = {
    'X-OAUTH-IDENTITY-DOMAIN-NAME':'OauthDomain',
	'grant_type': 'password',
    'username': args.userName,
    'password': args.passWord,
    'scope': 'primeiro-acesso.insert.credenciais'
}
try:
    logging.info('Pegando o token de acesso')
    token = requests.post(args.oamUrl + '/oauth2/rest/token', data=getTokenRequest, auth=(args.oamTokenUser, args.oamTokenPass), verify=False)
    pass
except Exception as e:
    raise e
logging.info('Token recebido')
# print(json.loads(token.text)['access_token'])
jsonToken = json.loads(token.text)

if 'access_token' in jsonToken:
    validateRequest = {
        # 'grant_type': 'oracle-idm:/oauth/grant-type/resource-access-token/jwt',
        # 'oracle_token_action': 'validate',
        'X-OAUTH-IDENTITY-DOMAIN-NAME':'OauthDomain',
		'scope': 'primeiro-acesso.insert.credenciais',
        'access_token': jsonToken['access_token']
    }
else:
    logging.error('Não foi possível pegar um token.')
    logging.info(jsonToken)
    sys.exit(100)

logging.info("Iniciando espera para iniciar as chamadas...")
time.sleep( args.requestInterval / 1000 )
logging.info("Fim da espera.")

logging.info('Fazendo 100 chamadas de validação...')

if args.oamUrlVal is not None:
    urlValidator = args.oamUrlVal
else:
    urlValidator = args.oamUrl
count = 0
while count < 100:
    try:
        resultValidator = requests.post(urlValidator + '/oauth2/rest/token/info?access_token=', data=validateRequest, auth=(args.oamValidatorUser, args.oamValidatorPass), verify=False)
        jsonValidator = json.loads(resultValidator.text)
        if 'successful' in jsonValidator and jsonValidator['successful'] == True:
            logging.info(returnSuccess('Sucesso'))
        else:
            print(resultValidator.text)
            logging.error(returnError('Erro na validação'))
        pass
    except Exception as e:
        print(resultValidator.text)
        raise e
    count += 1
