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

app = Flask(__name__)

# ========== CONFIGURATION ==========
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

JWT_GITHUB_URL = "https://raw.githubusercontent.com/AmirZzzw/info-api/refs/heads/main/jwt.json"

REGION_LANG = {"ME": "ar", "IND": "hi", "ID": "id", "VN": "vi", "TH": "th", 
               "BD": "bn", "PK": "ur", "TW": "zh", "CIS": "ru", "SAC": "es", "BR": "pt"}
# ===================================

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_jwt_token_from_github():
    """Get JWT token from GitHub repository"""
    try:
        response = requests.get(JWT_GITHUB_URL, timeout=10)
        response.raise_for_status()
        
        tokens_data = response.json()
        
        if not tokens_data:
            raise Exception("No tokens found in GitHub file")
        
        # Select a random token from the list
        selected_token = random.choice(tokens_data)
        jwt_token = selected_token.get('token')
        
        if not jwt_token:
            raise Exception("Token field not found in data")
        
        print(f"✅ JWT token loaded from GitHub ({len(tokens_data)} tokens available)")
        return jwt_token
        
    except Exception as e:
        print(f"❌ Failed to load JWT from GitHub: {e}")
        return None

def rotate_jwt_token():
    """Get a fresh JWT token (rotate if needed)"""
    return get_jwt_token_from_github()

# ========== ACCOUNT FUNCTIONS ==========

def encrypt_aes(hex_data):
    """Encrypt data with AES"""
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    padded_data = pad(bytes.fromhex(hex_data), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return binascii.hexlify(encrypted_data).decode()

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

def call_api_with_jwt(idd, region):
    """Call API with JWT token from GitHub"""
    # Get JWT token from GitHub
    token = get_jwt_token_from_github()
    if not token:
        raise Exception(f"Failed to get JWT token from GitHub for region {region}")
    
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
    except requests.exceptions.HTTPError as e:
        if response.status_code == 401:
            print("⚠️ JWT token expired, trying with another token...")
            # Try with another token
            token = rotate_jwt_token()
            if token:
                headers['Authorization'] = f'Bearer {token}'
                response = requests.post(endpoint, headers=headers, data=data, timeout=30)
                response.raise_for_status()
                return response.content.hex()
        raise
    except requests.exceptions.RequestException as e:
        print(f"API request failed: {e}")
        raise

# ========== FLASK ROUTES ==========

@app.route('/accinfo', methods=['GET'])
def get_player_info():
    try:
        uid = request.args.get('uid')
        region = request.args.get('region', 'ME').upper()
        
        if not uid:
            return jsonify({"error": "UID parameter is required"}), 400
        
        # Create protobuf message
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        protobuf_data = message.SerializeToString()
        hex_data = binascii.hexlify(protobuf_data).decode()
        
        # Encrypt the data
        encrypted_hex = encrypt_aes(hex_data)
        
        # Call API with JWT from GitHub
        print(f"\n📡 Processing request for UID: {uid}, Region: {region}")
        api_response = call_api_with_jwt(encrypted_hex, region)
        
        if not api_response:
            return jsonify({"error": "Empty response from API"}), 400
        
        # Parse response
        message = AccountPersonalShowInfo()
        message.ParseFromString(bytes.fromhex(api_response))
        
        # Convert to JSON
        result = MessageToDict(message)
        result['Powered By'] = ['Sidka Shop']
        result['note'] = 'JWT token loaded from GitHub repository'
        
        return jsonify(result)
        
    except ValueError:
        return jsonify({"error": "Invalid UID format"}), 400
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"error": f"Failure: {str(e)}"}), 500

@app.route('/test-jwt', methods=['GET'])
def test_jwt():
    """Test endpoint to check JWT token from GitHub"""
    try:
        token = get_jwt_token_from_github()
        if token:
            # Try to decode the token to show info
            try:
                parts = token.split('.')
                if len(parts) >= 2:
                    payload_part = parts[1]
                    padding = 4 - len(payload_part) % 4
                    if padding != 4:
                        payload_part += '=' * padding
                    decoded = base64.urlsafe_b64decode(payload_part)
                    data = json.loads(decoded)
                    
                    return jsonify({
                        "success": True,
                        "message": "JWT token loaded successfully",
                        "token_preview": token[:50] + "...",
                        "token_data": {
                            "account_id": data.get('account_id'),
                            "nickname": data.get('nickname'),
                            "region": data.get('noti_region'),
                            "exp": data.get('exp')
                        }
                    })
            except:
                return jsonify({
                    "success": True,
                    "message": "JWT token loaded successfully",
                    "token_preview": token[:50] + "..."
                })
        else:
            return jsonify({
                "success": False,
                "message": "Failed to load JWT token"
            }), 500
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    # Test if we can get JWT token
    jwt_status = "healthy" if get_jwt_token_from_github() else "unhealthy"
    
    return jsonify({
        "status": "healthy",
        "jwt_source": "healthy",
        "service": "FreeFire API",
        "mode": "JWT from GitHub repository",
        "github_url": JWT_GITHUB_URL,
        "timestamp": datetime.now().isoformat()
    })

# ========== MAIN EXECUTION ==========

if __name__ == "__main__":
    print("=" * 70)
    print("🎮 FREEFIRE API - JWT FROM GITHUB")
    print(f"📁 Loading tokens from: {JWT_GITHUB_URL}")
    print("=" * 70)
    
    # Test JWT loading on startup
    test_token = get_jwt_token_from_github()
    if test_token:
        print(f"✅ JWT token loaded successfully")
        print(f"📝 Token preview: {test_token[:50]}...")
    else:
        print("❌ Failed to load JWT token from GitHub")
    
    port = int(os.environ.get('PORT', 5552))
    
    print(f"\n🚀 Starting server on http://0.0.0.0:{port}")
    print("\n📋 Available endpoints:")
    print("  GET /accinfo?uid=123456789&region=ME  - Get player info")
    print("  GET /test-jwt                         - Test JWT token loading")
    print("  GET /health                           - Health check")
    print("\n" + "=" * 70)
    
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
