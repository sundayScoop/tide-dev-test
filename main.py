from flask import *
from ecdsa import SigningKey, NIST256p
import base64
import hashlib
from ecdsa.util import sigencode_der, sigdecode_der

app = Flask(__name__)

key_list = {}
id_count = 0

@app.route('/Key', methods=['GET'])
def get_all_keys():
    global key_list
    return jsonify(key_list)

@app.route('/Key/<ID>', methods=['GET'])
def get_key(ID):
    global key_list
    if int(ID) in key_list:
        
        key = key_list.get(int(ID))

        response = {
            "Id": int(ID),    # Had to return ID even tho ID is supplied in URL
            "Key": key
        }
       
        return jsonify(response)
    else:
        return '', 500 # Had to specifically return status code 500
    
@app.route('/Key', methods=['POST', 'PUT'])
def add_key():
    global key_list
    global id_count
    
    req = request.get_json()
    key_string = req['Key']
    
    if request.method == 'POST':
        key_id = id_count
        
    elif request.method == 'PUT':
        key_id = req['Id']  # Id is supplied in PUT request, but not POST
       
    key_list[key_id] = key_string  # Add key + key_id to dict
    
    if request.method == 'POST': # Could be simplified further, reducing IF statements
        response = {} # Create reponse 'json'
        response['Id'] = int(key_id)
        response['Key'] = key_string
        id_count+=1  # Because you added a key
        return jsonify(response)
        
    elif request.method == 'PUT': 
        return '', 200 # Return 200 OK

@app.route('/Key/<id>', methods=['DELETE'])
def del_key(id):
    global key_list

    key_list.pop(int(id))

    return ''

@app.route('/signature', methods=['GET'])
def encrypt_msg():
    global key_list
    
    key_id = request.args.get('keyId')
    msg = base64.urlsafe_b64decode(request.args.get('message')) # Decode from URL safe base64

    key_pem = key_list.get(int(key_id))
    
    if key_pem.find("PRIVATE KEY") != -1: # Check key exists
        secret_key = SigningKey.from_pem(key_pem, hashlib.sha3_256) # Create key from pem + sha3_256 hash
        signature = secret_key.sign_deterministic(msg, sigencode=sigencode_der) # Sign key with openssl compatibility

        encoded_sig = base64.b64encode(signature) # Encode in base64

        return (encoded_sig)
    else:
        return ''

if __name__ == '__main__':
    app.run(port=8080)
