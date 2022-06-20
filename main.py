from flask import *
from ecdsa import SigningKey, NIST256p
import base64
import hashlib
import requests
from ecdsa.util import sigencode_der, sigdecode_der
import hmac
import json
import http
app = Flask(__name__)

key_list = {}
id_count = 0

@app.route('/Key', methods=['GET'])
def get_all_keys():
    global key_list
    return jsonify(key_list)

@app.route('/Key/<id>', methods=['GET'])
def get_key(id):
    global key_list
    if int(id) in key_list:
        response = {
            "Key": key_list.get(int(id))
        }
        #print("GETTTT" + str(id))
        #print(key_list.get(int(id)))
        print("GET")
        print(str(response))
        return jsonify(response)
    else:
        return '', 500
    
@app.route('/Key', methods=['POST', 'PUT'])
def add_key():
    global key_list
    global id_count
    req = request.get_json()
    
    key_string = req['Key']
    if request.method == 'POST':
        key_id = id_count
        #print("POST" + str(key_id))
        #print(key_string)
        #print("----")
    elif request.method == 'PUT':
        key_id = req['Id']
        #print("PUT" + str(key_id))
        #print(key_string)
        #print("----")
        
    
    response = {}
    
    key_list[key_id] = key_string
        
    response['Id'] = int(key_id)
    response['Key'] = key_string
    
    if request.method == 'POST': 
        id_count+=1
        
    print(str(response))
        
    if request.method == 'POST': return jsonify(response)
    else: return '', 200

@app.route('/Key/<id>', methods=['DELETE'])
def del_key(id):
    global key_list

    key_list.pop(int(id))

    return ''

@app.route('/signature', methods=['GET'])
def encrypt_msg():
    global key_list
    
    key_id = request.args.get('keyId')
    msg = base64.urlsafe_b64decode(request.args.get('message'))

    key_pem = key_list.get(int(key_id))
    if key_pem.find("PRIVATE KEY") != -1:
        secret_key = SigningKey.from_pem(key_pem, hashlib.sha3_256)    
        signature = secret_key.sign_deterministic(msg, sigencode=sigencode_der)

    
        encoded_sig = base64.b64encode(signature)

        return (encoded_sig)
    else:
        return ''


def addPemKeyStructure(key):
    top = "-----BEGIN EC PRIVATE KEY-----\n"
    bottom = "\n-----END EC PRIVATE KEY-----"
    key = top + key[:64] + "\n" + key[64:128] + "\n" + key[128:] + bottom
    return key

if __name__ == '__main__':
    app.run(port=8080)
