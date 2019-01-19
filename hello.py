# -*- coding: UTF-8 -*-
import os
import time
import json
import hashlib
import OpenSSL
import requests
import xmltodict
from random import choice, randint
from flask import Flask, request, make_response, render_template, redirect, request

app = Flask(__name__)

APPID = ''
SECRET = ''
REDIRECT_URI = ''
RESPONSE_TYPE = 'code'
SCOPE = 'snsapi_userinfo'


@app.route('/')
def hello_world():
    return 'hello world!'


#通过code换取网页授权access_token,openid
@app.route('/web-access-token')
def web_access_token():
    code = request.args.get('code',0)
    url = f'https://api.weixin.qq.com/sns/oauth2/access_token?appid={APPID}&secret={SECRET}&code={code}&grant_type=authorization_code'
    r = requests.get(url)
    str_dict = json.loads(r.text)
    openid = str_dict['openid']
    html = render_template('redrain.html')
    response = make_response(html)
    response.set_cookie('openid', openid)
    return response


#获取code
@app.route('/user/hl')
def user_hl():
    url = f'https://open.weixin.qq.com/connect/oauth2/authorize?appid={APPID}&redirect_uri={REDIRECT_URI}&response_type=code&scope={SCOPE}#wechat_redirect'
    print(url)
    return redirect(url)


#微信验证
@app.route('/<path>')
def file(path):
    base_dir = os.path.dirname(__file__)
    resp = make_response(open(os.path.join(base_dir, path)).read())
    return resp


@app.route('/hl')
def hl():
    return render_template('redrain.html')


@app.route('/getredpack')
def getRedpack():
    act_name = '年会'
    send_name = ''
    total_amount = randint(100, 600)

    fcount = len(open('redpack.txt','r').readlines())
    if fcount < 200:
        openId = request.cookies.get('openid')
    else:
        openId = 'aa'

    with open('redpack.txt', 'a+') as f:
        f.write(str(total_amount))
        f.write('\n')


    # 构造红包数据
    mch_id = '10023384'
    props = {
        'act_name': act_name,
        'client_ip': '120.25.63.206',
        'mch_billno': mch_id + get_time() + getRangeStr(4),
        'mch_id': mch_id,
        'nonce_str': getRangeStr(32),
        're_openid': openId,
        'remark': 'remark',
        'send_name': send_name,
        'total_amount': total_amount,
        'total_num': '1',
        'wishing': 'wishing',
        'wxappid': '',
        'key':''
    }
    props['sign'] = signFun(props)
    data = json_xml(props).encode('utf8')
    print(data)

    # 发送红包
    cert = p12_to_pem('apiclient_cert')
    res = requests.post('https://api.mch.weixin.qq.com/mmpaymkttransfers/sendredpack', data=data, cert=cert)
    
    result = xml_json(res.text)['xml']

    return result['return_msg']


redpack = {
    'success': '发放红包成功',
    'error': '出现问题，请重试',
    'repeat': '你已经领取过该红包，请勿重复领取',
    'actError': '活动无效'
}

activate = {
    '问卷调查红包': '761E52960C497C77E05012AC8E4E0A32'#数据库活动表的id,输入问卷调查找到此活动
}


def m_dict(obj, props=[]):
    result = {}
    temp = obj.__dict__ if hasattr(obj, '__dict__') else obj
    target = temp if len(props)==0 else props
    for i in target:
        if not i.startswith('_'):
            try:
                result[i] = getattr(obj, i) if hasattr(obj, i) else obj[i]
            except:
                pass
    return result


def getRangeStr(len):
    result = ''
    chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678'
    for i in range(len):
        result += choice(chars)
    return result


def get_time(formatStr='%Y%m%d%H%M%S'):
    return time.strftime(formatStr, time.localtime(time.time()))


def formateLen(instr, width):
    instr = str(instr)
    if len(instr)<width:
        return formateLen('0'+instr, width)
    else:
        return instr


def MD5(instr):
    return hashlib.md5(instr.encode('utf-8')).hexdigest()


def signFun(props):
    tempStr = ''
    key = props.pop('key')
    props = sorted(props.items())
    for prop in props:
        print(prop)
        #print(prop[0] + '' + prop[1])
        tempStr += (str(prop[0])+'='+str(prop[1])+'&')
    return MD5(tempStr+'key='+key).upper()


def json_xml(jsonstr):
    if 'xml' not in jsonstr:
        jsonstr = {'xml': jsonstr}

    jsonstr = json.dumps(jsonstr)
    print('-----')
    print(jsonstr)
    jsonstr = json.loads(jsonstr)
    print(jsonstr)
    return xmltodict.unparse(jsonstr)


def xml_json(xmlstr):
    return xmltodict.parse(xmlstr)
    # return json.dumps(xmlparse,indent=1)


def p12_to_pem(certname, pwd='10023384'):
    pem_name = certname + ".pem"
    f_pem = open(pem_name, 'wb')
    p12file = certname + ".p12"
    p12 = OpenSSL.crypto.load_pkcs12(open(p12file, 'rb').read(), pwd)
    f_pem.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, p12.get_privatekey()))
    f_pem.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, p12.get_certificate()))
    ca = p12.get_ca_certificates()
    if ca is not None:
        for cert in ca:
            f_pem.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
    f_pem.close()
    return pem_name


def getUUID(namespace='redpack', name='recode'):
    return uuid.uuid5(namespace, name)



