from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import requests
from flask import Flask, jsonify, request
from data_pb2 import AccountPersonalShowInfo
from google.protobuf.json_format import MessageToDict
import uid_generator_pb2
import threading
import time
import json
import base64
from datetime import datetime

app = Flask(__name__)

# ========== CONFIGURATION ==========
# JWT tokens for each region (you can manually enter them)
JWT_TOKENS = {
    "ME": "eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ.eyJhY2NvdW50X2lkIjoxNDE0Njc4NDQzOCwibmlja25hbWUiOiJzaWRrYcK54oGwwrnigbXCuSIsIm5vdGlfcmVnaW9uIjoiTUUiLCJsb2NrX3JlZ2lvbiI6Ik1FIiwiZXh0ZXJuYWxfaWQiOiI3ZGU0MGQ3ZTYwZTBmNGMwNDQyNTk4ZjhmMzkxNDA2NiIsImV4dGVybmFsX3R5cGUiOjQsInBsYXRfaWQiOjEsImNsaWVudF92ZXJzaW9uIjoiMS4xMTQuMTMiLCJlbXVsYXRvcl9zY29yZSI6MTAwLCJpc19lbXVsYXRvciI6dHJ1ZSwiY291bnRyeV9jb2RlIjoiSVIiLCJleHRlcm5hbF91aWQiOjQzNDY4NTY3MTAsInJlZ19hdmF0YXIiOjEwMjAwMDAwNywic291cmNlIjowLCJsb2NrX3JlZ2lvbl90aW1lIjowLCJjbGllbnRfdHlwZSI6Miwic2lnbmF0dXJlX21kNSI6Ijc0MjhiMjUzZGVmYzE2NDAxOGM2MDRhMWViYmZlYmRmIiwidXNpbmdfdmVyc2lvbiI6MSwicmVsZWFzZV9jaGFubmVsIjoiYW5kcm9pZCIsInJlbGVhc2VfdmVyc2lvbiI6Ik9CNTEiLCJleHAiOjE3NjYwNjA0NDh9.lY_7fz_Z__PDW6t9CoaXTaS_8ABOcZh16pYO6iThDz4",
    "BR": "",  # Add your BR token here
    "IND": "",  # Add your IND token here
    "US": "",  # Add your US token here
    "default": ""  # Add default token here
}

AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
# ===================================

jwt_token = None
jwt_lock = threading.Lock()

def check_jwt_validity(token):
    """Check if JWT token is valid and not expired"""
    if not token or not token.strip():
        return False, "Empty token"
    
    try:
        # Split token into parts
        parts = token.split('.')
        if len(parts) != 3:
            return False, "Invalid JWT format"
        
        # Decode payload (second part)
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
        
        decoded = base64.urlsafe_b64decode(payload)
        data = json.loads(decoded)
        
        # Check expiration
        if 'exp' in data:
            exp_timestamp = data['exp']
            current_timestamp = datetime.now().timestamp()
            
            if exp_timestamp < current_timestamp:
                time_left = exp_timestamp - current_timestamp
                return False, f"Token expired {abs(time_left):.0f} seconds ago"
            else:
                time_left = exp_timestamp - current_timestamp
                hours_left = time_left / 3600
                return True, f"Token valid for {hours_left:.1f} hours"
        else:
            return True, "Token has no expiration (valid)"
            
    except Exception as e:
        return False, f"Error decoding token: {str(e)}"

def ensure_jwt_token_sync(region):
    """Get JWT token for region"""
    global jwt_token
    
    with jwt_lock:
        # Get token from configuration
        token = JWT_TOKENS.get(region.upper(), JWT_TOKENS.get("default", ""))
        
        if not token:
            return None
        
        # Check token validity
        is_valid, message = check_jwt_validity(token)
        
        if is_valid:
            print(f"[✓] JWT for {region}: {message}")
            jwt_token = token
            return token
        else:
            print(f"[✗] JWT for {region}: {message}")
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

def encrypt_aes(hex_data, key=None, iv=None):
    """Encrypt data with AES"""
    if key is None:
        key = AES_KEY
    else:
        key = key.encode()[:16]
    
    if iv is None:
        iv = AES_IV
    else:
        iv = iv.encode()[:16]
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(bytes.fromhex(hex_data), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return binascii.hexlify(encrypted_data).decode()

def apis(idd, region):
    """Call the API with encrypted data"""
    global jwt_token
    
    token = ensure_jwt_token_sync(region)
    if not token:
        raise Exception(f"No valid JWT token for region {region}")
    
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
        response = requests.post(
            endpoint,
            headers=headers,
            data=data,
            timeout=30
        )
        response.raise_for_status()
        return response.content.hex()
    except requests.exceptions.RequestException as e:
        print(f"API request failed: {e}")
        raise

@app.route('/accinfo', methods=['GET'])
def get_player_info():
    try:
        uid = request.args.get('uid')
        region = request.args.get('region', 'ME').upper()
        custom_key = request.args.get('key')
        custom_iv = request.args.get('iv')
        
        if not uid:
            return jsonify({"error": "UID parameter is required"}), 400
        
        # Create protobuf message
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        protobuf_data = message.SerializeToString()
        hex_data = binascii.hexlify(protobuf_data).decode()
        
        # Encrypt the data
        encrypted_hex = encrypt_aes(hex_data, custom_key, custom_iv)
        
        # Call API
        api_response = apis(encrypted_hex, region)
        
        if not api_response:
            return jsonify({"error": "Empty response from API"}), 400
        
        # Parse response
        message = AccountPersonalShowInfo()
        message.ParseFromString(bytes.fromhex(api_response))
        
        # Convert to JSON
        result = MessageToDict(message)
        result['Powered By'] = ['Sidka Shop']
        
        return jsonify(result)
        
    except ValueError:
        return jsonify({"error": "Invalid UID format"}), 400
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"error": f"Failure: {str(e)}"}), 500

@app.route('/favicon.ico')
def favicon():
    return '', 404

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

@app.route('/checktoken')
def check_token():
    region = request.args.get('region', 'ME')
    token = JWT_TOKENS.get(region.upper(), "")
    
    if not token:
        return jsonify({
            "region": region,
            "has_token": False,
            "message": "No token configured for this region"
        })
    
    is_valid, message = check_jwt_validity(token)
    
    return jsonify({
        "region": region,
        "has_token": True,
        "token_valid": is_valid,
        "message": message,
        "token_preview": token[:50] + "..." if len(token) > 50 else token
    })

@app.route('/tokens')
def list_tokens():
    tokens_info = {}
    for region, token in JWT_TOKENS.items():
        if token:
            is_valid, message = check_jwt_validity(token)
            tokens_info[region] = {
                "has_token": True,
                "valid": is_valid,
                "message": message,
                "length": len(token)
            }
        else:
            tokens_info[region] = {
                "has_token": False,
                "message": "No token configured"
            }
    
    return jsonify(tokens_info)

if __name__ == "__main__":
    # Disable SSL warnings
    import urllib3
    urllib3.disable_warnings()
    
    print("=" * 50)
    print("JWT-Based FreeFire API Server")
    print("=" * 50)
    
    # Check all configured tokens
    print("\nChecking configured JWT tokens:")
    for region, token in JWT_TOKENS.items():
        if token:
            is_valid, message = check_jwt_validity(token)
            status = "✓" if is_valid else "✗"
            print(f"  {status} {region}: {message}")
        else:
            print(f"  ⚠ {region}: No token configured")
    
    print(f"\nStarting server on http://0.0.0.0:5552")
    print("Available endpoints:")
    print("  GET /accinfo?uid=123456789&region=ME")
    print("  GET /checktoken?region=ME")
    print("  GET /tokens")
    print("  GET /health")
    print("=" * 50)
    
    app.run(host="0.0.0.0", port=5552, debug=False)
