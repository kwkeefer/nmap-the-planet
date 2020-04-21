import ipaddress
from flask import Flask, request
import concurrent.futures

app = Flask(__name__)


def split_cidr_into_chunks(cidr: str, max_cider_prefix: int):
    """
    Checks to see if the CIDR needs to be broken up.
    Max size is the largest CIDR prefix

    For example - if you pass in 10.0.0.0/8 and your max cider prefix is 24,
    you will be returned a list of /24 subnets.

    If you pass in 10.0.0.0/25 and your max cider prefix is 24, your cidr
    will be returned inside of a list.)

    :param cidr:  CIDR to check (example: 10.0.0.0/8)
    :param max_cider_prefix:  Maximum cidr prefix allowed (example: 24)
    :return: list of CIDR(s) (example: [10.0.0.0/24, 10.0.1.0/24, ...] or [10.0.0.0/25)
    """
    net4 = ipaddress.ip_network(cidr)
    if net4.num_addresses > 2 ** (32 - max_cider_prefix):
        cidrs = [str(x) for x in net4.subnets(new_prefix=max_cider_prefix)]
        return cidrs
    else:
        return [cidr]


@app.route('/health')
def healthcheck():
    """
    A simple application healthcheck
    :return: "I'm alive!"
    """
    return "I'm alive!"


def main():
    pass


@app.route('/submit_scan', methods=['POST'])
def submit_scan():
    r = request.get_json()
    max_cidr_prefix = r['max_cidr_prefix']
    cidr = r['cidr']
    arguments = r['arguments']
    workers = r.get('workers', 25)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        executor.map(main)


if __name__ == "__main__":
    # app.run(host='0.0.0.0')
    subnets = split_cidr_into_chunks("10.0.0.0/24", max_cider_prefix=25)
    print(subnets)
