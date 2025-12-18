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
import threading
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

# ========== TOKEN MANAGER ==========
class TokenManager:
    def __init__(self):
        self.tokens = {}  # {region: {"token": "...", "expiry": timestamp}}
        self.lock = threading.Lock()
    
    def get_token(self, region):
        """Get JWT token for region, create if expired"""
        with self.lock:
            region = region.upper()
            now = time.time()
            
            # Check if we have a valid token
            if region in self.tokens:
                token_data = self.tokens[region]
                # Check if token is still valid (5 minutes)
                if token_data["expiry"] > now:
                    print(f"🔑 Using cached JWT token for {region}")
                    return token_data["token"]
            
            # Create new token
            print(f"🔄 No valid token for {region}, creating fresh JWT...")
            token = self._create_jwt_token(region)
            if token:
                # Store for 5 minutes (JWT tokens expire fast)
                self.tokens[region] = {
                    "token": token,
                    "expiry": now + 300  # 5 minutes
                }
                print(f"✅ JWT Token stored for {region}")
                return token
            return None
    
    def _create_jwt_token(self, region):
        """Create a JWT token using major_login"""
        try:
            print(f"🔄 Step 1: Creating guest account for {region}")
            # Step 1: Create guest account
            guest_data = create_acc(region)
            if not guest_data:
                print("❌ Failed to create guest account")
                return None
            
            print(f"🔄 Step 2: Getting access token")
            # Step 2: Get access token
            token_data = token_grant(guest_data['uid'], guest_data['password'])
            if not token_data:
                print("❌ Failed to get access token")
                return None
            
            print(f"🔄 Step 3: MajorLogin for JWT")
            # Step 3: MajorLogin for JWT
            login_data = major_login_simple(
                token_data['access_token'], 
                token_data['open_id'], 
                region
            )
            
            if login_data and login_data.get('jwt_token'):
                print(f"✅ JWT Token created successfully for {region}")
                return login_data['jwt_token']
            
            print(f"❌ Failed to get JWT token")
            return None
            
        except Exception as e:
            print(f"❌ JWT creation failed: {e}")
            return None

# ایجاد global instance
token_manager = TokenManager()

# ========== SIMPLIFIED MAJOR LOGIN ==========
def major_login_simple(access_token, open_id, region):
    """Simplified version of major_login"""
    try:
        lang = REGION_LANG.get(region.upper(), "en")
        
        # Create a simple payload
        payload = {
            "access_token": access_token,
            "open_id": open_id,
            "region": region,
            "lang": lang,
            "client_type": 2,
            "platform": "android"
        }
        
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

        # Convert payload to protobuf format
        payload_bytes = CrEaTe_ProTo({
            2: access_token,
            3: open_id,
            5: 102000007,
            6: 4,
            7: 1,
            13: 1,
            15: lang,
            16: 1,
            17: 1
        })
        
        encrypted_payload = binascii.hexlify(payload_bytes).decode()
        encrypted_data = encrypt_api(encrypted_payload)
        final_payload = bytes.fromhex(encrypted_data)

        response = requests.post(url, headers=headers, data=final_payload, verify=False, timeout=30)
        
        print(f"🔍 MajorLogin Status: {response.status_code}")
        
        if response.status_code == 200 and len(response.text) > 10:
            # Try to find JWT token in response
            response_text = response.text
            
            # Look for JWT pattern
            import re
            jwt_pattern = r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
            match = re.search(jwt_pattern, response_text)
            
            if match:
                jwt_token = match.group(0)
                print(f"✅ Found JWT token: {jwt_token[:50]}...")
                return {"jwt_token": jwt_token}
            else:
                print(f"⚠️ No JWT found in response, using access_token as fallback")
                # Return access_token as fallback
                return {"jwt_token": access_token}
        
        return None
        
    except Exception as e:
        print(f"❌ MajorLogin failed: {e}")
        return None

# ========== BASIC ACCOUNT FUNCTIONS ==========
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

def create_acc(region, max_retries=3):
    """Create guest account"""
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
                    print(f"[1/3] Guest account created: {uid}")
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
    """Get access token"""
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
            print(f"[2/3] Access token granted: {access_token[:30]}...")
            return {"access_token": access_token, "open_id": open_id}
        return None
    except Exception as e:
        print(f"[ERROR] Token grant failed: {e}")
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

def call_api_with_jwt(idd, region):
    """Call API with JWT token"""
    # Get JWT token
    jwt_token = token_manager.get_token(region)
    if not jwt_token:
        raise Exception(f"Failed to get JWT token for region {region}")
    
    endpoint = get_api_endpoint(region)
    
    headers = {
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
        'Connection': 'Keep-Alive',
        'Expect': '100-continue',
        'Authorization': f'Bearer {jwt_token}',
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': 'OB49',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    
    try:
        data = bytes.fromhex(idd)
        
        # First attempt
        response = requests.post(
            endpoint, 
            headers=headers, 
            data=data, 
            timeout=15,
            verify=False
        )
        
        print(f"🔍 API Response Status: {response.status_code}")
        
        # If 401, refresh token and retry
        if response.status_code == 401:
            print(f"⚠️ JWT Token expired for {region}, refreshing...")
            # Delete old token
            with token_manager.lock:
                if region in token_manager.tokens:
                    del token_manager.tokens[region]
            
            # Get new token
            jwt_token = token_manager.get_token(region)
            if jwt_token:
                headers['Authorization'] = f'Bearer {jwt_token}'
                response = requests.post(
                    endpoint, 
                    headers=headers, 
                    data=data, 
                    timeout=15,
                    verify=False
                )
        
        if response.status_code != 200:
            print(f"❌ API Error {response.status_code}: {response.text[:200]}")
            raise Exception(f"API returned {response.status_code}")
            
        return response.content.hex()
        
    except requests.exceptions.RequestException as e:
        print(f"❌ API request failed: {e}")
        raise

# ========== FLASK ROUTES ==========
@app.route('/accinfo', methods=['GET'])
def get_player_info():
    try:
        uid = request.args.get('uid')
        region = request.args.get('region', 'ME').upper()
        
        if not uid:
            return jsonify({"error": "UID parameter is required"}), 400
        
        print(f"\n🎯 NEW REQUEST - UID: {uid}, Region: {region}")
        
        # Create protobuf message
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        protobuf_data = message.SerializeToString()
        hex_data = binascii.hexlify(protobuf_data).decode()
        
        # Encrypt the data
        encrypted_hex = encrypt_aes(hex_data)
        
        # Call API با JWT token
        print(f"📡 Calling API with JWT token for {region}...")
        api_response = call_api_with_jwt(encrypted_hex, region)
        
        if not api_response:
            return jsonify({"error": "Empty response from API"}), 400
        
        # Parse response
        message = AccountPersonalShowInfo()
        message.ParseFromString(bytes.fromhex(api_response))
        
        # Convert to JSON
        result = MessageToDict(message)
        result['Powered By'] = ['Sidka Shop']
        result['token_type'] = 'jwt_token'
        
        return jsonify(result)
        
    except ValueError:
        return jsonify({"error": "Invalid UID format"}), 400
    except Exception as e:
        print(f"❌ Error: {e}")
        return jsonify({"error": f"Failure: {str(e)}"}), 500

@app.route('/test', methods=['GET'])
def test_endpoint():
    """تست JWT token creation"""
    region = request.args.get('region', 'ME').upper()
    
    try:
        token = token_manager.get_token(region)
        if token:
            # Check if it looks like a JWT
            is_jwt = token.count('.') == 2
            
            return jsonify({
                "success": True,
                "region": region,
                "message": "JWT system working" if is_jwt else "Token system working",
                "has_token": True,
                "is_jwt": is_jwt,
                "token_preview": token[:50] + "..."
            })
        else:
            return jsonify({
                "success": False,
                "region": region,
                "message": "Failed to get token"
            }), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "healthy",
        "service": "FreeFire API",
        "mode": "JWT Token System",
        "timestamp": datetime.now().isoformat()
    })

# ========== MAIN ==========
if __name__ == "__main__":
    print("=" * 70)
    print("🚀 FREEFIRE API - JWT TOKEN SYSTEM")
    print("✅ JWT tokens cached for 5 minutes")
    print("✅ Proper authentication flow")
    print("=" * 70)
    
    port = int(os.environ.get('PORT', 5552))
    
    print(f"\n📡 Starting on http://0.0.0.0:{port}")
    print("\n📋 Endpoints:")
    print("  GET /accinfo?uid=...&region=...  - Player info with JWT")
    print("  GET /test?region=ME              - Test JWT system")
    print("  GET /health                      - Health check")
    print("\n" + "=" * 70)
    
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
