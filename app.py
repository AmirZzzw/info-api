from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import requests
from flask import Flask, jsonify, request
from data_pb2 import AccountPersonalShowInfo
from google.protobuf.json_format import MessageToDict
import uid_generator_pb2
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
# ===================================

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ========== ACCOUNT CREATION FUNCTIONS (WITH RETRY) ==========

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

def get_api_token(jwt_token, region):
    """Get specific token for GetPlayerPersonalShow API"""
    try:
        if region.upper() in ["ME", "TH"]:
            url = "https://clientbp.common.ggbluefox.com/GetToken"
        else:
            url = "https://clientbp.ggblueshark.com/GetToken"
        
        headers = {
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
            'Connection': 'Keep-Alive',
            'Authorization': f'Bearer {jwt_token}',
            'X-Unity-Version': '2018.4.11f1',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        
        # داده خالی بفرست
        response = requests.post(url, headers=headers, data=b'', timeout=10, verify=False)
        
        if response.status_code == 200 and response.text:
            print(f"[5/5] API token obtained")
            return response.text.strip()  # این توکن اصلیه
        else:
            print(f"[WARNING] GetToken failed: {response.status_code}")
            return jwt_token  # fallback به توکن اصلی
    
    except Exception as e:
        print(f"[ERROR] Get API token failed: {e}")
        return jwt_token  # fallback
        
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
    """Create a fresh account and get PROPER API token"""
    print(f"\n{'='*50}")
    print(f"CREATING FRESH ACCOUNT FOR REGION: {region}")
    print(f"{'='*50}")
    
    try:
        # Step 1-4: مثل قبل
        guest_data = create_acc(region)
        if not guest_data:
            raise Exception("Failed to create guest account")
        
        token_data = token_grant(guest_data['uid'], guest_data['password'])
        if not token_data:
            raise Exception("Failed to get access token")
        
        register_data = major_register(token_data['access_token'], token_data['open_id'], region)
        if not register_data:
            print("[WARNING] MajorRegister failed, continuing...")
        
        login_data = major_login(guest_data['uid'], guest_data['password'], 
                               token_data['access_token'], token_data['open_id'], region)
        
        if not login_data or not login_data['jwt_token']:
            raise Exception("Failed to get JWT token")
        
        print(f"[SUCCESS] Fresh JWT token created for {region}")
        
        # Step 5: Get PROPER API token
        print(f"[5/5] Getting API-specific token...")
        api_token = get_api_token(login_data['jwt_token'], region)
        
        return api_token  # این توکن اصلی برای API هست
            
    except Exception as e:
        print(f"[ERROR] Failed to create fresh account: {e}")
        return None

# ========== API FUNCTIONS ==========

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

def call_api_with_fresh_token(idd, region):
    """Call API with a fresh JWT token"""
    # Create fresh account and get token
    token = create_fresh_account(region)
    if not token:
        raise Exception(f"Failed to create fresh account for region {region}")
    
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
    
    try:
        data = bytes.fromhex(idd)
        response = requests.post(endpoint, headers=headers, data=data, timeout=30)
        response.raise_for_status()
        return response.content.hex()
    except requests.exceptions.RequestException as e:
        print(f"API request failed: {e}")
        raise

# ========== FLASK ROUTES ==========

# ========== TOKEN STORAGE ==========
TOKEN_STORE = {}  # {region: {"token": "...", "created_at": timestamp, "account_id": "..."}}

def get_or_create_token(region):
    """Get existing token or create new one if expired"""
    region = region.upper()
    
    # اگر توکن برای این منطقه وجود داره و هنوز معتبره
    if region in TOKEN_STORE:
        token_data = TOKEN_STORE[region]
        # چک کن ببین توکن هنوز معتبره (مثلاً کمتر از ۵ دقیقه از ساختش گذشته)
        if time.time() - token_data["created_at"] < 300:  # ۵ دقیقه
            print(f"✅ Using existing token for {region} (age: {int(time.time() - token_data['created_at'])}s)")
            return token_data["token"]
    
    # اگر توکن نداریم یا منقضی شده، جدید بساز
    print(f"🔄 Creating fresh token for {region}")
    token = create_fresh_account(region)
    
    if token:
        TOKEN_STORE[region] = {
            "token": token,
            "created_at": time.time(),
            "region": region
        }
        print(f"✅ Token created and stored for {region}")
        return token
    
    return None

# ========== UPDATE get_player_info ==========
@app.route('/accinfo', methods=['GET'])
def get_player_info():
    try:
        uid = request.args.get('uid')
        region = request.args.get('region', 'ME').upper()
        
        if not uid:
            return jsonify({"error": "UID parameter is required"}), 400
        
        # Step 1: Get or create token
        print(f"\n🎮 REQUEST - UID: {uid}, Region: {region}")
        token = get_or_create_token(region)
        
        if not token:
            return jsonify({"error": "Failed to get/create token"}), 500
        
        # Step 2: Create protobuf message
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        protobuf_data = message.SerializeToString()
        hex_data = binascii.hexlify(protobuf_data).decode()
        
        # Step 3: Encrypt the data
        encrypted_hex = encrypt_aes(hex_data)
        
        # Step 4: Call API with token
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
        
        print(f"📡 Calling API with existing token...")
        response = requests.post(endpoint, headers=headers, 
                               data=bytes.fromhex(encrypted_hex), timeout=30)
        
        # Step 5: Handle 401 errors (token expired)
        if response.status_code == 401:
            print(f"🔐 Token expired (401), creating new one...")
            # حذف توکن منقضی شده
            if region in TOKEN_STORE:
                del TOKEN_STORE[region]
            
            # توکن جدید بساز
            token = create_fresh_account(region)
            if not token:
                return jsonify({"error": "Failed to create new token after 401"}), 500
            
            TOKEN_STORE[region] = {
                "token": token,
                "created_at": time.time(),
                "region": region
            }
            
            # دوباره با توکن جدید امتحان کن
            headers['Authorization'] = f'Bearer {token}'
            response = requests.post(endpoint, headers=headers, 
                                   data=bytes.fromhex(encrypted_hex), timeout=30)
        
        if response.status_code != 200:
            return jsonify({"error": f"API failed: {response.status_code}"}), 500
            
        api_response = response.content.hex()
        
        # Parse response
        message = AccountPersonalShowInfo()
        message.ParseFromString(bytes.fromhex(api_response))
        
        # Convert to JSON
        result = MessageToDict(message)
        result['Powered By'] = ['Sidka Shop']
        result['note'] = f'Using token created at {datetime.now().isoformat()}'
        result['token_age'] = f"{int(time.time() - TOKEN_STORE.get(region, {}).get('created_at', 0))}s"
        
        return jsonify(result)
        
    except ValueError:
        return jsonify({"error": "Invalid UID format"}), 400
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"error": f"Failure: {str(e)}"}), 500

# ========== ADD TOKEN INFO ENDPOINT ==========
@app.route('/token_status', methods=['GET'])
def token_status():
    """Show current token status"""
    status = {}
    for region, data in TOKEN_STORE.items():
        age = int(time.time() - data["created_at"])
        status[region] = {
            "age_seconds": age,
            "age_minutes": age // 60,
            "is_expired": age > 300,  # ۵ دقیقه
            "token_preview": data["token"][:30] + "..."
        }
    return jsonify(status)

@app.route('/test', methods=['GET'])
def test_account_creation():
    """Test endpoint to create account without API call"""
    region = request.args.get('region', 'ME').upper()
    
    try:
        token = create_fresh_account(region)
        if token:
            return jsonify({
                "success": True,
                "region": region,
                "message": "Fresh account created successfully",
                "token_preview": token[:50] + "..."
            })
        else:
            return jsonify({
                "success": False,
                "region": region,
                "message": "Failed to create account"
            }), 500
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "healthy",
        "service": "FreeFire API",
        "mode": "Fresh account per request",
        "timestamp": datetime.now().isoformat()
    })

# ========== MAIN EXECUTION ==========

if __name__ == "__main__":
    print("=" * 70)
    print("🎮 FREEFIRE API - FRESH ACCOUNT PER REQUEST")
    print("📝 No token storage, fresh JWT for every request")
    print("=" * 70)
    
    port = int(os.environ.get('PORT', 5552))
    
    print(f"\n🚀 Starting server on http://0.0.0.0:{port}")
    print("\n📋 Available endpoints:")
    print("  GET /accinfo?uid=123456789&region=ME  - Get player info (creates fresh account)")
    print("  GET /test?region=ME                   - Test account creation")
    print("  GET /health                           - Health check")
    print("\n" + "=" * 70)
    
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
