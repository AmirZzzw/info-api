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

ACCOUNT_NAME_PREFIX = "SidkaShop"
PASSWORD_PREFIX = "SidkaShop"
GARENA_ENCODED = "U0lES0FTSE9Q"
# ===================================

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ========== SIMPLE TOKEN MANAGER ==========
class SimpleTokenManager:
    def __init__(self):
        self.tokens = {}  # {region: {"token": "...", "expiry": timestamp}}
        self.lock = threading.Lock()
    
    def get_token(self, region):
        """Get access_token (not JWT)"""
        with self.lock:
            region = region.upper()
            now = time.time()
            
            # Check if we have a valid token
            if region in self.tokens:
                token_data = self.tokens[region]
                # Check if token is still valid (30 minutes)
                if token_data["expiry"] > now:
                    print(f"🔑 Using cached access_token for {region}")
                    return token_data["token"]
            
            # Create new token
            print(f"🔄 Creating fresh access_token for {region}")
            token_data = self._create_fresh_access_token(region)
            if token_data:
                # Store for 30 minutes
                self.tokens[region] = {
                    "token": token_data["access_token"],
                    "expiry": now + 1800  # 30 minutes
                }
                print(f"✅ access_token stored for {region}")
                return token_data["access_token"]
            return None
    
    def _create_fresh_access_token(self, region):
        """Create a fresh access_token (simple)"""
        try:
            print(f"🔄 Step 1: Creating guest account")
            guest_data = create_acc(region)
            if not guest_data:
                return None
            
            print(f"🔄 Step 2: Getting access_token")
            token_data = token_grant(guest_data['uid'], guest_data['password'])
            return token_data
            
        except Exception as e:
            print(f"❌ Token creation failed: {e}")
            return None

# Import threading
import threading
token_manager = SimpleTokenManager()

# ========== ACCOUNT FUNCTIONS ==========
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
                    print(f"[1/2] Guest account created: {uid}")
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
        
        result = response.json()
        access_token = result.get("access_token")
        open_id = result.get("open_id")
        
        if access_token and open_id:
            print(f"[2/2] access_token obtained: {access_token[:30]}...")
            return {"access_token": access_token, "open_id": open_id}
        return None
    except Exception as e:
        print(f"[ERROR] Token grant failed: {e}")
        return None

# ========== ENCRYPTION FUNCTIONS ==========
def encrypt_aes(hex_data):
    """Encrypt data with AES"""
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    padded_data = pad(bytes.fromhex(hex_data), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return binascii.hexlify(encrypted_data).decode()

# ========== MAIN API CALL ==========
@app.route('/accinfo', methods=['GET'])
def get_player_info():
    try:
        uid = request.args.get('uid')
        
        if not uid:
            return jsonify({"error": "UID parameter is required"}), 400
        
        print(f"\n🎯 REQUEST - UID: {uid}")
        
        # Create protobuf message
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        protobuf_data = message.SerializeToString()
        hex_data = binascii.hexlify(protobuf_data).decode()
        
        # Encrypt the data
        encrypted_hex = encrypt_aes(hex_data)
        
        # Try different approaches
        result = try_all_approaches(encrypted_hex, uid)
        
        if result:
            return jsonify(result)
        else:
            return jsonify({"error": "All approaches failed"}), 500
        
    except ValueError:
        return jsonify({"error": "Invalid UID format"}), 400
    except Exception as e:
        print(f"❌ Error: {e}")
        return jsonify({"error": f"Failure: {str(e)}"}), 500

def try_all_approaches(encrypted_hex, uid):
    """Try different API calling approaches"""
    
    approaches = [
        ("METHOD 1: Direct with access_token", try_direct_access_token),
        ("METHOD 2: With custom headers", try_custom_headers),
        ("METHOD 3: Simple POST", try_simple_post),
    ]
    
    for method_name, method_func in approaches:
        print(f"\n🔄 Trying {method_name}...")
        try:
            result = method_func(encrypted_hex)
            if result:
                print(f"✅ {method_name} SUCCESS!")
                result['method_used'] = method_name
                return result
        except Exception as e:
            print(f"❌ {method_name} failed: {e}")
            continue
    
    return None

def try_direct_access_token(encrypted_hex):
    """Try with direct access_token"""
    # Get fresh access_token
    token_data = create_acc_and_token("SG")
    if not token_data:
        return None
    
    access_token = token_data["access_token"]
    
    # Try different endpoints
    endpoints = [
        "https://clientbp.ggblueshark.com/GetPlayerPersonalShow",
        "https://client.ind.freefiremobile.com/GetPlayerPersonalShow",
        "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
    ]
    
    headers = {
        'User-Agent': 'UnityPlayer/2018.4.11f1',
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    
    for endpoint in endpoints:
        print(f"🔍 Trying endpoint: {endpoint}")
        try:
            response = requests.post(
                endpoint,
                headers=headers,
                data=bytes.fromhex(encrypted_hex),
                timeout=15,
                verify=False
            )
            
            print(f"🔍 Status: {response.status_code}")
            
            if response.status_code == 200:
                return parse_response(response.content)
            elif response.status_code != 401:
                print(f"⚠️ Unexpected status: {response.status_code}")
        except Exception as e:
            print(f"❌ Endpoint {endpoint} error: {e}")
    
    return None

def try_custom_headers(encrypted_hex):
    """Try with custom headers"""
    token_data = create_acc_and_token("SG")
    if not token_data:
        return None
    
    access_token = token_data["access_token"]
    
    headers_list = [
        {
            'User-Agent': 'UnityPlayer/2018.4.11f1',
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Unity-Version': '2018.4.11f1',
        },
        {
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
        },
        {
            'User-Agent': 'Garena Free Fire',
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
    ]
    
    endpoint = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
    
    for i, headers in enumerate(headers_list):
        print(f"🔍 Trying header set {i+1}")
        try:
            response = requests.post(
                endpoint,
                headers=headers,
                data=bytes.fromhex(encrypted_hex),
                timeout=15,
                verify=False
            )
            
            if response.status_code == 200:
                return parse_response(response.content)
        except:
            continue
    
    return None

def try_simple_post(encrypted_hex):
    """Simple POST without auth"""
    endpoint = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
    
    headers = {
        'User-Agent': 'UnityPlayer/2018.4.11f1',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    
    try:
        response = requests.post(
            endpoint,
            headers=headers,
            data=bytes.fromhex(encrypted_hex),
            timeout=15,
            verify=False
        )
        
        if response.status_code == 200:
            return parse_response(response.content)
    except:
        pass
    
    return None

def create_acc_and_token(region):
    """Quick account and token creation"""
    try:
        guest_data = create_acc(region)
        if not guest_data:
            return None
        
        token_data = token_grant(guest_data['uid'], guest_data['password'])
        return token_data
    except:
        return None

def parse_response(content):
    """Parse protobuf response"""
    try:
        message = AccountPersonalShowInfo()
        message.ParseFromString(content)
        result = MessageToDict(message)
        result['Powered By'] = ['Sidka Shop']
        return result
    except Exception as e:
        print(f"❌ Parse error: {e}")
        return None

# ========== TEST ENDPOINTS ==========
@app.route('/test_token', methods=['GET'])
def test_token():
    """Test token creation"""
    try:
        token_data = create_acc_and_token("SG")
        if token_data:
            return jsonify({
                "success": True,
                "access_token": token_data["access_token"][:50] + "...",
                "open_id": token_data["open_id"],
                "length": len(token_data["access_token"])
            })
        else:
            return jsonify({"success": False, "error": "Failed"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "healthy",
        "service": "FreeFire API - Multi-approach",
        "timestamp": datetime.now().isoformat()
    })

# ========== MAIN ==========
if __name__ == "__main__":
    print("=" * 70)
    print("🚀 FREEFIRE API - MULTI-APPROACH SYSTEM")
    print("✅ Trying multiple methods to bypass 401")
    print("=" * 70)
    
    port = int(os.environ.get('PORT', 5552))
    
    print(f"\n📡 Starting on http://0.0.0.0:{port}")
    print("\n📋 Endpoints:")
    print("  GET /accinfo?uid=...  - Player info (tries multiple methods)")
    print("  GET /test_token       - Test token creation")
    print("  GET /health           - Health check")
    print("\n" + "=" * 70)
    
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
