import concurrent.futures
import logging
import ipaddress
from flask import Flask, request
from retrying import retry
import requests

logger = logging.getLogger(__name__)
logger.propagate = 0
logging.basicConfig(level=logging.INFO)
console = logging.StreamHandler()
logger.addHandler(console)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', '%m-%d-%Y %H:%M:%S')
console.setFormatter(formatter)

app = Flask(__name__)
# postgres_api_address = "postgres-api"
# scanner_address = "scanner"
postgres_api_address = "http://localhost:5000"
scanner_address = "http://localhost:5555"


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
    :return: list of CIDR(s) (example: [10.0.0.0/24, 10.0.1.0/24, ...] or [10.0.0.0/25])
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


def add_scan_to_database(arguments, cidr):
    logger.info(f"Adding scan to database: {cidr} {arguments}")
    response = requests.post(url=f"{postgres_api_address}/add_scan", json={
        "arguments": arguments,
        "cidr": cidr
    })
    if response.status_code == 200:
        scan_id = response.json()['scan_id']
        logger.info(f"scan_id is {scan_id}!")
        return scan_id
    else:
        logger.error(response.text)


def add_scan_results_to_database(scan_results, scan_id):
    logger.info("HELP!")
    for entry in scan_results:
        scan_entry = {
            "scan_id": scan_id,
            "ip_address": entry['addresses']['ipv4'],
            "hostnames": entry.get("hostnames", None),
            "status": entry['status']['state'],
            "status_reason": entry['status']['reason'],
            "tcp": entry.get("tcp", None),
            "udp": entry.get("udp", None)
        }
        logger.info(scan_entry)
        logger.info(f"Adding scan results to database for scan_id {scan_id}.")
        response = requests.post(url=f"{postgres_api_address}/add_result", json=scan_entry)
        if response.status_code == 200:
            logger.info(f"Result added successfully.")
        else:
            logger.error(response.text)


@retry(wait_exponential_multiplier=1000, wait_exponential_max=10000, stop_max_attempt_number=20)
def run_scan(args):
    cidr = args['cidr']
    arguments = args['arguments']
    scan_id = args['scan_id']

    logger.info(f"Submitting {cidr} using scan_id {scan_id}.")
    scan_results = requests.post(url=f"{scanner_address}/scan", json={
        "cidr": cidr,
        "arguments": arguments
    })

    if scan_results.status_code == 200:
        logger.info(f"Scan completed for {scan_id}:\n{scan_results.text}")
        add_scan_results_to_database(scan_results.json(), scan_id)
    else:
        logger.error(scan_results.text)
        raise scan_results.text


@app.route('/submit_scan', methods=['POST'])
def submit_scan():
    r = request.get_json()
    logger.info(f"Request received:\n{r}")
    max_cidr_prefix = r.get("max_cidr_prefix", 24)
    cidr = r['cidr']
    arguments = r['arguments']
    workers = r.get('workers', 25)
    scan_id = add_scan_to_database(arguments=arguments, cidr=cidr)

    split_cidrs = split_cidr_into_chunks(cidr=cidr, max_cider_prefix=max_cidr_prefix)
    run_scan_args_list = []

    for cidr in split_cidrs:
        run_scan_args_list.append(
            {
                "cidr": cidr,
                "arguments": arguments,
                "scan_id": scan_id
            }
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        executor.map(run_scan, run_scan_args_list)

    executor.shutdown(wait=True)

    return "Hi"


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80, debug=True)
