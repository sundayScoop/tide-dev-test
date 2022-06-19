from flask import *
from ecdsa import SigningKey, NIST256p
import requests
app = Flask(__name__)

key_list = {}
id_count = 0

@app.route('/Key', methods=['GET'])
def get_all_keys():
    return jsonify(key_list)

@app.route('/Key/<id>', methods=['GET'])
def get_key(id):

    response = {
        "key": key_list.get(int(id))
    }

    return jsonify(response)

@app.route('/Key', methods=['POST'])
def add_key():
    global id_count

    new_key_string = request.form.get('key')
    #new_key_string = addPemKeyStructure(new_key_string)

    #new_secret_key = SigningKey.from_pem(new_key_string)

    key_list[id_count] = new_key_string

    response = {}
    response['id'] = id_count
    response['key'] = new_key_string

    id_count += 1

    return jsonify(response)

def addPemKeyStructure(key):
    top = "-----BEGIN EC PRIVATE KEY-----\n"
    bottom = "\n-----END EC PRIVATE KEY-----"
    key = top + key[:64] + "\n" + key[64:128] + "\n" + key[128:] + bottom
    return key

if __name__ == '__main__':
    app.run()
