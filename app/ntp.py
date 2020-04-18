from flask import Flask, request, jsonify
import nmap
import json

app = Flask(__name__)
nm = nmap.PortScanner()


def run_scan(cidr, arguments):
    print(f"Running scan against {cidr} with args: {arguments}")
    nm.scan(hosts=cidr, arguments=arguments)
    results = []
    for host in nm.all_hosts():
        results.append(nm[host])
    return json.dumps(results)


@app.errorhandler(500)
def internal_error(error=None):
    message = {
        'status': 500,
        'message': error
    }
    resp = jsonify(message)
    resp.status_code = 500
    return resp


@app.route('/health')
def healthcheck():
    """ 
    A simple application healthcheck
    :return: "I'm alive!"
    """
    return "I'm alive!"


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


if __name__ == "__main__":
    app.run(host='0.0.0.0')
