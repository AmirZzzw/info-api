# -*- coding: utf-8 -*-
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import requests
from flask import Flask, jsonify, request
import time
import json
import base64
from datetime import datetime
import hmac
import hashlib
import string
import random
import codecs
import urllib3
import os
import sys
import traceback

app = Flask(__name__)

# ========== CONFIGURATION ==========
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
GARENA_KEY = bytes.fromhex("32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533")

REGION_LANG = {"ME": "ar", "IND": "hi", "ID": "id", "VN": "vi", "TH": "th", 
               "BD": "bn", "PK": "ur", "TW": "zh", "CIS": "ru", "SAC": "es", "BR": "pt"}
ACCOUNT_NAME_PREFIX = "SidkaShop"
PASSWORD_PREFIX = "SidkaShop"
GARENA_ENCODED = "U0lES0FTSE9Q"

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ========== HELPER FUNCTIONS ==========
def generate_random_name(base_name):
    """Generate name with exponent numbers"""
    exponent_digits = {'0': '⁰', '1': '¹', '2': '²', '3': '³', '4': '⁴', 
                      '5': '⁵', '6': '⁶', '7': '⁷', '8': '⁸', '9': '⁹'}
    number = random.randint(1, 99999)
    number_str = f"{number:05d}"
    exponent_str = ''.join(exponent_digits[digit] for digit in number_str)
    return f"{base_name[:7]}{exponent_str}"

def generate_custom_password(prefix):
    """Generate password with GARENA encoded"""
    garena_decoded = base64.b64decode(GARENA_ENCODED).decode('utf-8')
    characters = string.ascii_uppercase + string.digits
    random_part1 = ''.join(random.choice(characters) for _ in range(5))
    random_part2 = ''.join(random.choice(characters) for _ in range(5))
    return f"{prefix}_{random_part1}_{garena_decoded}_{random_part2}"

def EnC_Vr(N):
    """Varint encoding"""
    if N < 0: 
        return b''
    H = []
    while True:
        BesTo = N & 0x7F 
        N >>= 7
        if N: 
            BesTo |= 0x80
        H.append(BesTo)
        if not N: 
            break
    return bytes(H)

def CrEaTe_VarianT(field_number, value):
    """Create variant field"""
    field_header = (field_number << 3) | 0
    return EnC_Vr(field_header) + EnC_Vr(value)

def CrEaTe_LenGTh(field_number, value):
    """Create length-delimited field"""
    field_header = (field_number << 3) | 2
    encoded_value = value.encode() if isinstance(value, str) else value
    return EnC_Vr(field_header) + EnC_Vr(len(encoded_value)) + encoded_value

def CrEaTe_ProTo(fields):
    """Create protobuf message"""
    packet = bytearray()    
    for field, value in fields.items():
        if isinstance(value, dict):
            nested_packet = CrEaTe_ProTo(value)
            packet.extend(CrEaTe_LenGTh(field, nested_packet))
        elif isinstance(value, int):
            packet.extend(CrEaTe_VarianT(field, value))           
        elif isinstance(value, str) or isinstance(value, bytes):
            packet.extend(CrEaTe_LenGTh(field, value))           
    return packet

def encrypt_api(plain_text):
    """Encrypt for API"""
    plain_text = bytes.fromhex(plain_text)
    key_bytes = AES_KEY
    iv = AES_IV
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def encode_string(original):
    """Encode string for field_14"""
    keystream = [0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37,
                 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30]
    encoded = ""
    for i in range(len(original)):
        orig_byte = ord(original[i])
        key_byte = keystream[i % len(keystream)]
        result_byte = orig_byte ^ key_byte
        encoded += chr(result_byte)
    return {"open_id": original, "field_14": encoded}

def to_unicode_escaped(s):
    """Convert to unicode escaped"""
    return ''.join(c if 32 <= ord(c) <= 126 else f'\\u{ord(c):04x}' for c in s)

# ========== ACCOUNT CREATION ==========
def create_acc(region, max_retries=3):
    """Step 1: Create guest account"""
    for attempt in range(max_retries):
        try:
            password = generate_custom_password(PASSWORD_PREFIX)
            data = f"password={password}&client_type=2&source=2&app_id=100067"
            message = data.encode('utf-8')
            signature = hmac.new(GARENA_KEY, message, hashlib.sha256).hexdigest()
            
            url = "https://100067.connect.garena.com/oauth/guest/register"
            headers = {
                "User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
                "Authorization": "Signature " + signature,
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept-Encoding": "gzip",
                "Connection": "Keep-Alive"
            }
            
            response = requests.post(url, headers=headers, data=data, timeout=30, verify=False)
            
            if response.status_code == 200:
                result = response.json()
                if 'uid' in result:
                    uid = result['uid']
                    print(f"[1/5] Guest account created: {uid}")
                    return {"uid": uid, "password": password}
            else:
                print(f"[ATTEMPT {attempt + 1}/{max_retries}] Create account failed: {response.status_code}")
                
        except Exception as e:
            print(f"[ATTEMPT {attempt + 1}/{max_retries}] Create account error: {e}")
        
        if attempt < max_retries - 1:
            time.sleep(2 ** attempt)
    
    print(f"[ERROR] Failed to create account after {max_retries} attempts")
    return None

def token_grant(uid, password):
    """Step 2: Get access token"""
    try:
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {
            "Accept-Encoding": "gzip",
            "Connection": "Keep-Alive",
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
        }
        body = {
            "uid": uid,
            "password": password,
            "response_type": "token",
            "client_type": "2",
            "client_secret": GARENA_KEY,
            "client_id": "100067"
        }
        
        response = requests.post(url, headers=headers, data=body, timeout=30, verify=False)
        response.raise_for_status()
        
        if 'open_id' in response.json():
            open_id = response.json()['open_id']
            access_token = response.json()["access_token"]
            print(f"[2/5] Token granted for: {uid}")
            return {"access_token": access_token, "open_id": open_id}
        return None
    except Exception as e:
        print(f"[ERROR] Token grant failed: {e}")
        return None

def major_register(access_token, open_id, region):
    """Step 3: MajorRegister"""
    try:
        if region.upper() in ["ME", "TH"]:
            url = "https://loginbp.common.ggbluefox.com/MajorRegister"
        else:
            url = "https://loginbp.ggblueshark.com/MajorRegister"
        
        name = generate_random_name(ACCOUNT_NAME_PREFIX)
        
        headers = {
            "Accept-Encoding": "gzip",
            "Authorization": "Bearer",   
            "Connection": "Keep-Alive",
            "Content-Type": "application/x-www-form-urlencoded",
            "Expect": "100-continue",
            "Host": "loginbp.ggblueshark.com" if region.upper() not in ["ME", "TH"] else "loginbp.common.ggbluefox.com",
            "ReleaseVersion": "OB51",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
            "X-GA": "v1 1",
            "X-Unity-Version": "2018.4."
        }

        lang_code = REGION_LANG.get(region.upper(), "en")
        payload = {
            1: name,
            2: access_token,
            3: open_id,
            5: 102000007,
            6: 4,
            7: 1,
            13: 1,
            14: codecs.decode(to_unicode_escaped(encode_string(open_id)['field_14']), 'unicode_escape').encode('latin1'),
            15: lang_code,
            16: 1,
            17: 1
        }

        payload_bytes = CrEaTe_ProTo(payload)
        encrypted_payload = binascii.hexlify(payload_bytes).decode()
        
        response = requests.post(url, headers=headers, data=bytes.fromhex(encrypt_api(encrypted_payload)), verify=False, timeout=30)
        
        if response.status_code == 200:
            print(f"[3/5] MajorRegister successful: {name}")
            return {"name": name}
        else:
            print(f"[WARNING] MajorRegister status: {response.status_code}")
            return None
    except Exception as e:
        print(f"[ERROR] MajorRegister error: {e}")
        return None

def major_login(uid, password, access_token, open_id, region):
    """Step 4: MajorLogin to get JWT Token"""
    try:
        lang = REGION_LANG.get(region.upper(), "en")
        
        payload_parts = [
            b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.114.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02',
            lang.encode("ascii"),
            b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019118692\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
        ]
        
        payload = b''.join(payload_parts)
        
        if region.upper() in ["ME", "TH"]:
            url = "https://loginbp.common.ggbluefox.com/MajorLogin"
        else:
            url = "https://loginbp.ggblueshark.com/MajorLogin"
        
        headers = {
            "Accept-Encoding": "gzip",
            "Authorization": "Bearer",
            "Connection": "Keep-Alive",
            "Content-Type": "application/x-www-form-urlencoded",
            "Expect": "100-continue",
            "Host": "loginbp.ggblueshark.com" if region.upper() not in ["ME", "TH"] else "loginbp.common.ggbluefox.com",
            "ReleaseVersion": "OB51",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
            "X-GA": "v1 1",
            "X-Unity-Version": "2018.4.11f1"
        }

        data = payload
        data = data.replace(b'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390', access_token.encode())
        data = data.replace(b'1d8ec0240ede109973f3321b9354b44d', open_id.encode())
        
        d = encrypt_api(data.hex())
        final_payload = bytes.fromhex(d)

        response = requests.post(url, headers=headers, data=final_payload, verify=False, timeout=30)
        
        if response.status_code == 200 and len(response.text) > 10:
            jwt_start = response.text.find("eyJ")
            if jwt_start != -1:
                jwt_token = response.text[jwt_start:]
                second_dot = jwt_token.find(".", jwt_token.find(".") + 1)
                if second_dot != -1:
                    jwt_token = jwt_token[:second_dot + 44]
                    account_id = decode_jwt_token(jwt_token)
                    print(f"[4/5] JWT Token obtained")
                    return {"jwt_token": jwt_token, "account_id": account_id}
        
        return {"jwt_token": "", "account_id": "N/A"}
    except Exception as e:
        print(f"[ERROR] MajorLogin failed: {e}")
        return {"jwt_token": "", "account_id": "N/A"}

def decode_jwt_token(jwt_token):
    """Decode account_id from JWT token"""
    try:
        parts = jwt_token.split('.')
        if len(parts) >= 2:
            payload_part = parts[1]
            padding = 4 - len(payload_part) % 4
            if padding != 4:
                payload_part += '=' * padding
            decoded = base64.urlsafe_b64decode(payload_part)
            data = json.loads(decoded)
            account_id = data.get('account_id') or data.get('external_id')
            if account_id:
                return str(account_id)
    except Exception as e:
        print(f"[WARNING] JWT decode failed: {e}")
    return "N/A"

def create_fresh_account(region):
    """Create a fresh account and get JWT token"""
    print(f"\n{'='*50}")
    print(f"CREATING FRESH ACCOUNT FOR REGION: {region}")
    print(f"{'='*50}")
    
    try:
        # Step 1: Create guest account
        guest_data = create_acc(region)
        if not guest_data:
            raise Exception("Failed to create guest account")
        
        # Step 2: Get access token
        token_data = token_grant(guest_data['uid'], guest_data['password'])
        if not token_data:
            raise Exception("Failed to get access token")
        
        # Step 3: MajorRegister
        register_data = major_register(token_data['access_token'], token_data['open_id'], region)
        if not register_data:
            print("[WARNING] MajorRegister failed, continuing...")
        
        # Step 4: MajorLogin for JWT
        login_data = major_login(guest_data['uid'], guest_data['password'], 
                               token_data['access_token'], token_data['open_id'], region)
        
        if login_data and login_data['jwt_token']:
            print(f"[SUCCESS] Fresh JWT token created for {region}")
            return login_data['jwt_token']
        else:
            raise Exception("Failed to get JWT token")
            
    except Exception as e:
        print(f"[ERROR] Failed to create fresh account: {e}")
        return None

def get_api_endpoint(region):
    """Get API endpoint based on region"""
    endpoints = {
        "IND": "https://client.ind.freefiremobile.com/GetPlayerPersonalShow",
        "BR": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "US": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "SAC": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "NA": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "ME": "https://clientbp.ggblueshark.com/GetPlayerPersonalShow",
        "default": "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
    }
    return endpoints.get(region.upper(), endpoints["default"])

def encrypt_aes(hex_data):
    """Encrypt data with AES"""
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    padded_data = pad(bytes.fromhex(hex_data), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return binascii.hexlify(encrypted_data).decode()

# ========== IMPORT PROTOBUF MODULES ==========
try:
    # First try to import directly
    import data_pb2
    import uid_generator_pb2
    print("✅ Successfully imported protobuf modules")
except ImportError as e:
    print(f"❌ Failed to import protobuf modules: {e}")
    print("Trying alternative import methods...")
    
    # Try adding current directory to path
    current_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, current_dir)
    
    try:
        import data_pb2
        import uid_generator_pb2
        print("✅ Imported protobuf modules using sys.path")
    except ImportError as e2:
        print(f"❌ Still failed: {e2}")
        # Create fallback mock modules
        print("⚠️ Using mock modules - API may not work correctly")
        
        # Create minimal uid_generator mock
        class MockUidGenerator:
            class uid_generator:
                def __init__(self):
                    self.saturn_ = 0
                    self.garena = 0
                
                def SerializeToString(self):
                    return b'\x08\x00\x10\x00'
        
        uid_generator_pb2 = MockUidGenerator()
        
        # Create minimal data_pb2 mock
        class MockDataPB2:
            class AccountPersonalShowInfo:
                def __init__(self):
                    pass
                def ParseFromString(self, data):
                    return 0
                @staticmethod
                def __call__():
                    return MockDataPB2.AccountPersonalShowInfo()
        
        data_pb2 = MockDataPB2()

# ========== FLASK ROUTES ==========
@app.route('/accinfo', methods=['GET'])
def get_player_info():
    try:
        uid = request.args.get('uid')
        region = request.args.get('region', 'ME').upper()
        
        if not uid:
            return jsonify({"error": "UID parameter is required"}), 400
        
        print(f"\n🎮 STARTING REQUEST - UID: {uid}, Region: {region}")
        print(f"📅 Time: {datetime.now().isoformat()}")
        
        # Step 1: Create protobuf message
        try:
            message = uid_generator_pb2.uid_generator()
            message.saturn_ = int(uid)
            message.garena = 1
            protobuf_data = message.SerializeToString()
            hex_data = binascii.hexlify(protobuf_data).decode()
            print(f"✅ Created protobuf data: {len(protobuf_data)} bytes")
        except Exception as e:
            print(f"❌ Protobuf creation failed: {e}")
            return jsonify({"error": f"Protobuf creation failed: {str(e)}"}), 500
        
        # Step 2: Encrypt the data
        try:
            encrypted_hex = encrypt_aes(hex_data)
            print(f"✅ Encrypted data: {len(encrypted_hex)//2} bytes")
        except Exception as e:
            print(f"❌ Encryption failed: {e}")
            return jsonify({"error": f"Encryption failed: {str(e)}"}), 500
        
        # Step 3: Create fresh account
        try:
            print("🔐 Creating fresh account...")
            start_time = time.time()
            token = create_fresh_account(region)
            account_creation_time = time.time() - start_time
            print(f"⏱️ Account creation took: {account_creation_time:.2f} seconds")
            
            if not token:
                raise Exception("Failed to create fresh account")
                
            print(f"✅ Got JWT token (length: {len(token)})")
        except Exception as e:
            print(f"❌ Account creation failed: {e}")
            return jsonify({"error": f"Account creation failed: {str(e)}"}), 500
        
        # Step 4: Prepare API request
        endpoint = get_api_endpoint(region)
        headers = {
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
            'Connection': 'Keep-Alive',
            'Expect': '100-continue',
            'Authorization': f'Bearer {token}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': 'OB49',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        
        # Step 5: Call API
        try:
            print(f"📡 Calling API endpoint: {endpoint}")
            print(f"📊 Payload size: {len(encrypted_hex)//2} bytes")
            
            start_time = time.time()
            response = requests.post(endpoint, headers=headers, 
                                   data=bytes.fromhex(encrypted_hex), 
                                   timeout=30, verify=False)
            api_call_time = time.time() - start_time
            
            print(f"⏱️ API call took: {api_call_time:.2f} seconds")
            print(f"📋 Response status: {response.status_code}")
            print(f"📦 Response size: {len(response.content)} bytes")
            
            if response.status_code != 200:
                print(f"❌ API returned error: {response.status_code}")
                print(f"Response preview: {response.text[:200]}")
                return jsonify({
                    "error": f"API failed: {response.status_code}",
                    "response_preview": response.text[:200] if response.text else "Empty response"
                }), 500
            
            api_response = response.content.hex()
            print(f"✅ API call successful, response: {len(api_response)//2} bytes")
            
        except requests.exceptions.Timeout:
            print("❌ API request timed out")
            return jsonify({"error": "API request timed out"}), 504
        except requests.exceptions.RequestException as e:
            print(f"❌ API request failed: {e}")
            return jsonify({"error": f"API request failed: {str(e)}"}), 500
        
        # Step 6: Parse response
        try:
            message = data_pb2.AccountPersonalShowInfo()
            message.ParseFromString(bytes.fromhex(api_response))
            
            # Convert to JSON
            from google.protobuf.json_format import MessageToDict
            result = MessageToDict(message)
            result['Powered_By'] = 'Sidka Shop'
            result['request_metadata'] = {
                'uid': uid,
                'region': region,
                'account_creation_time': f"{account_creation_time:.2f}s",
                'api_call_time': f"{api_call_time:.2f}s",
                'total_time': f"{account_creation_time + api_call_time:.2f}s"
            }
            
            print(f"✅ Successfully parsed response")
            print(f"📊 Result keys: {list(result.keys())[:10]}...")
            
            return jsonify(result)
            
        except Exception as e:
            print(f"❌ Failed to parse API response: {e}")
            print(f"Response hex preview: {api_response[:100]}...")
            return jsonify({
                "error": f"Failed to parse API response: {str(e)}",
                "raw_response_hex": api_response[:500] + "..." if len(api_response) > 500 else api_response
            }), 500
        
    except ValueError as e:
        print(f"❌ Invalid UID format: {e}")
        return jsonify({"error": "Invalid UID format. Must be numeric."}), 400
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        traceback.print_exc()
        return jsonify({
            "error": f"Internal server error: {str(e)}",
            "traceback": traceback.format_exc()[-500:] if app.debug else "Enable debug mode for traceback"
        }), 500

@app.route('/test', methods=['GET'])
def test_endpoint():
    """Simple test endpoint"""
    return jsonify({
        "status": "online",
        "service": "FreeFire API",
        "version": "1.0",
        "timestamp": datetime.now().isoformat()
    })

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "healthy",
        "service": "FreeFire API",
        "timestamp": datetime.now().isoformat(),
        "environment": "Vercel" if "VERCEL" in os.environ else "Local"
    })

@app.route('/tokens', methods=['GET'])
def list_tokens():
    """List current tokens (empty for fresh account approach)"""
    return jsonify({
        "tokens": {},
        "note": "Using fresh account per request - no tokens stored",
        "timestamp": datetime.now().isoformat()
    })

# ========== ERROR HANDLERS ==========
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        "error": "Internal server error",
        "details": str(error) if app.debug else "Contact administrator"
    }), 500

# ========== MAIN EXECUTION ==========
if __name__ == "__main__":
    print("=" * 70)
    print("🎮 FREEFIRE API - FRESH ACCOUNT PER REQUEST")
    print("📝 Enhanced debugging version")
    print("=" * 70)
    
    port = int(os.environ.get('PORT', 5552))
    
    print(f"\n🚀 Starting server on http://0.0.0.0:{port}")
    print("\n📋 Available endpoints:")
    print("  GET /accinfo?uid=123456789&region=ME  - Get player info")
    print("  GET /test                             - Test endpoint")
    print("  GET /health                           - Health check")
    print("  GET /tokens                           - List tokens")
    print("\n" + "=" * 70)
    
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
