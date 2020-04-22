from flask import Flask, request, jsonify
import nmap
import logging
import json

logger = logging.getLogger(__name__)
logger.propagate = 0
logging.basicConfig(level=logging.INFO)
console = logging.StreamHandler()
logger.addHandler(console)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', '%m-%d-%Y %H:%M:%S')
console.setFormatter(formatter)

app = Flask(__name__)
nm = nmap.PortScanner()


def run_scan(cidr, arguments):
    """
    :param cidr: CIDR to execute NMAP scan against.
    :param arguments:  Arguments to pass to NMAP.  Same as command line arguments.  eg -sA
    :return: list of json results from hosts or empty list if no hosts were found
    """
    print(f"Running scan against {cidr} with args: {arguments}")
    nm.scan(hosts=cidr, arguments=arguments)
    results = []
    for host in nm.all_hosts():
        results.append(nm[host])
    return json.dumps(results)


@app.route('/scan', methods=['POST'])
def accept_scan():
    """
    Accepts an nmap scan request.
    Takes POST methods at /scan URI.
    POST body needs to be a json object with 'cidr' and 'argument' keys.
    :return: scan results
    """
    try:
        r = request.get_json()
        results = run_scan(cidr=r['cidr'], arguments=r['arguments'])
    except KeyError as e:
        return internal_error(f"KeyError: {e}")
    except Exception as e:
        return internal_error(f"Unknown Exception: {e}")
    return results


@app.errorhandler(500)
def internal_error(error=None):
    """
    :param error: Error message
    :return: json document of error
    """
    message = {
        'status': 500,
        'message': error
    }
    resp = jsonify(message)
    resp.status_code = 500

    logger.error(resp)
    return resp


@app.route('/health')
def healthcheck():
    """
    A simple application healthcheck
    :return: "I'm alive!"
    """
    return "I'm alive!"


if __name__ == "__main__":
    """ For debugging locally with built in Flask server. """
    app.run(host='0.0.0.0', port=5555, debug=True)
