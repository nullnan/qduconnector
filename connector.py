import requests as req
import argparse
import socket
# from requests.api import options
# from requests.sessions import session
from requests_toolbelt.adapters.socket_options import SocketOptionsAdapter

N = 104535806730412240171136332337963048337848444547204789715305577593872763880065294614168924165047901258187745104990138280090868451109676255984236732414141352965664603792609571298088368988442208850152168335702921942876580450799477225214956206533636808954545649497579096859478644379905984367815064502914725410929
E = 65537
headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHT ML, like Gecko) Chrome/96.0.4664.45 '
                  'Safari/537.36 '
    , 'JSESSIONID': None}
login_url = 'http://10.16.16.2:8080/eportal/InterFace.do?method=login'
timeout = None
DEBUG = False
args = None


def parseArgs():
    parser = argparse.ArgumentParser(prog='QDU Connector',
                                     description='A Tool used for login network',
                                     epilog='Have a nice day! :)')

    parser.add_argument('--debug', action='store_true', help='Show Debug Massage.')
    parser.add_argument('-l', '--login',
                        nargs=2,
                        required=True,
                        help='Login to Network. use -l USERNAME PASSWORD.')
    parser.add_argument('-i', '--interface',
                        nargs=1,
                        required=True,
                        help='The interface to login in.')
    parser.add_argument('-t', '--timeout',
                        nargs=1,
                        help='Set timeout for login process, default will be 5 seconds.')
    global args
    args = parser.parse_args()
    global DEBUG
    DEBUG = args.debug
    global timeout
    if args.timeout[0] is not None:
        timeout = int(args.timeout[0])
    if DEBUG:
        print('==DEBUG BEGIN==')
        print(args)
        print('==DEBUG END==')


class Utils(object):
    @staticmethod
    def encryptPassword(message: str, n, e) -> str:
        CHUNKSIZE = 126
        if len(message) > CHUNKSIZE:
            raise ValueError
        m = 0
        for i in message.encode('utf-8'):
            m = (m << 8) + i
        return hex(m ** e % n)[2:]

    #
    # CHUNKSIZE = 126
    # if len(message) > CHUNKSIZE:
    #     raise ValueError
    # message_byte = message.encode('utf-8')
    # m = 0
    # for i in message_byte:
    #     m = (m << 8) + i
    # return hex(m ** e % n)[2:]

    @staticmethod
    def makeSession(iface: str) -> req.Session:
        session = req.Session()
        options = [(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode('ascii'))]
        for prefix in ('http://', 'https://'):
            session.mount(prefix, SocketOptionsAdapter(socket_options=options))

        return session


def getWLANParams(session: req.Session) -> str:
    '''
    Return wlan_param : str

    This Function is used to get a JSSESSIONID and queryString.
    When you connnected, access any address or URL through HTTP
    to get a JavaScript code that leads you to Portal Page and
    gives a queryString contains your device's infomation include MAC and IP.
    '''
    response = session.get('http://123.123.123.123',
                           timeout=5 if timeout is None else timeout)  # Access a not extised address to get a JavaScript code.

    raw_param = response.text
    portal_url = raw_param.split('>')[1].split('<')[0][24:-1]  # For format check payload for details.
    headers['JSESSIONID'] = session.get(portal_url, timeout=5 if timeout is None else timeout).cookies['JSESSIONID']
    wlan_param = portal_url[41:]

    if DEBUG:
        print("==DEBUG BEGIN==")
        print("JSURL: %s" % portal_url)
        print("headers: %s" % headers)

    return wlan_param


def loginUser(session: req.Session, username: str, password: str, params: str, encrypt: bool = False) -> bool:
    '''
    Login user
    To login a user you need to send a POST to login_url,
    and set all the params correctly. The encrypt method is required when the 'passwordEncrypt' is True'
    '''
    # Build a login param
    post_param = {
        'userId': username,
        'password': password if not encrypt else Utils.encryptPassword(password, N, E),
        'service': 'internet',
        'queryString': params,
        'operatorPwd': None,
        'operatorUserId': None,
        'validcode': None,
        'passwordEncrypt': 'true' if encrypt else 'false'  # there require a javascirpt-style bool value
    }

    r = session.post(login_url, data=post_param, headers=headers, timeout=5 if timeout is None else timeout)

    r.encoding = 'utf-8'  # Notice: The respone encoded in 'GBK', Set the encoding to make the charater display correctly.
    if DEBUG:
        print('Respone :')
        print(r.json())
    return r.json()['result'] == 'success'


if __name__ == '__main__':
    parseArgs()
    iface = args.interface[0]
    session = Utils.makeSession(iface)

    wlan_param = getWLANParams(session)
    username = args.login[0]
    password = args.login[1]
    if loginUser(session, username, password, wlan_param, True):
        exit(0)
