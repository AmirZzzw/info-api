# api/index.py
import sys
import os

# مسیر فایل‌های اصلی رو اضافه کن
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from app import app
from flask import jsonify

# ایجاد یک WSGI application برای Vercel
application = app

# تابع handler مخصوص Vercel
def handler(request):
    from urllib.parse import parse_qs, urlparse
    
    # پارامترها رو از request بگیر
    parsed = urlparse(request['path'])
    query_params = parse_qs(request.get('queryStringParameters', {}))
    
    # درخواست رو به Flask بده
    with app.test_request_context(
        path=parsed.path,
        method=request['httpMethod'],
        query_string=request.get('queryStringParameters'),
        headers=request.get('headers', {})
    ):
        response = app.full_dispatch_request()
        return {
            'statusCode': response.status_code,
            'headers': dict(response.headers),
            'body': response.get_data(as_text=True)
}
