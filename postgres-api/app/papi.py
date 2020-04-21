import psycopg2
from configparser import ConfigParser
import atexit
from flask import Flask, request, jsonify
import json
import re

app = Flask(__name__)


def config(filename='database.ini', section='postgresql'):
    # create a parser
    parser = ConfigParser()
    # read config file
    parser.read(filename)

    # get section, default to postgresql
    db = {}
    if parser.has_section(section):
        params = parser.items(section)
        for param in params:
            db[param[0]] = param[1]
    else:
        raise Exception('Section {0} not found in the {1} file'.format(section, filename))

    return db


@app.route('/health')
def healthcheck():
    """
    A simple application healthcheck
    :return: "I'm alive!"
    """
    return "I'm alive!"


def create_tables():
    """ create tables in the PostgreSQL database"""
    commands = [
        """
        CREATE TABLE IF NOT EXISTS scan (
                id SERIAL PRIMARY KEY,
                arguments VARCHAR(70) NOT NULL,
                cidr VARCHAR(25) NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
            CREATE TABLE IF NOT EXISTS result (
            ip_address VARCHAR(25) NOT NULL,
            scan_id INT NOT NULL,
            FOREIGN KEY (scan_id)
                REFERENCES scan (id)
                ON UPDATE CASCADE ON DELETE CASCADE,
            PRIMARY KEY (scan_id , ip_address),
            hostnames VARCHAR,
            status VARCHAR(10) NOT NULL,
            status_reason VARCHAR(30),
            tcp VARCHAR,
            udp VARCHAR
    )
        """
    ]

    try:
        # create table one by one
        for command in commands:
            cur = conn.cursor()
            cur.execute(command)

        # commit the changes
        conn.commit()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)


@app.route('/add_scan', methods=['POST'])
def add_scan():
    try:
        cur = conn.cursor()
        r = request.get_json()

        # break sql injection
        arguments = re.sub("[^a-zA-Z0-9\-]", "", r['arguments'])
        cidr = re.sub("[^0-9\.\/]", "", r['cidr'])

        cur.execute(f"INSERT INTO scan(arguments, cidr) VALUES('{arguments}','{cidr}') RETURNING id;")
        scan_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
    except KeyError as e:
        cur.close()
        return internal_error(f"KeyError: {str(e)}")
    except Exception as e:
        cur.close()
        return internal_error(f"Unknown Exception: {str(e)}")
    return json.dumps({"scan_id": scan_id})


@app.route('/add_result', methods=['POST'])
def create_result():
    try:
        cur = conn.cursor()
        r = request.get_json()

        ip_address = r['ip_address']
        ip_address = re.sub("[^0-9\.\/]", "", ip_address)

        scan_id = r['scan_id']
        scan_id = re.sub("[^0-9]", "", scan_id)

        hostnames = r.get('hostnames', None)
        if hostnames: hostnames = re.sub("[^0-9a-zA-Z\/\.]", "", hostnames)

        status = re.sub("[^a-zA-Z]", "", status)
        status = r['status']

        status_reason = r.get('status_reason', None)
        if status_reason: status_reason = re.sub("[^a-zA-Z]", "", status_reason)

        tcp = r.get('tcp', None)
        if tcp:
            tcp = json.dumps(tcp)

        udp = r.get('udp', None)
        if udp:
            udp = json.dumps(udp)

        cur.execute(f"""
        INSERT INTO result("ip_address", "scan_id", "hostnames", "status", "status_reason", "tcp", "udp")
        VALUES('{ip_address}', '{scan_id}', '{hostnames}','{status}','{status_reason}','{tcp}', '{udp}');
        """)

        conn.commit()
        cur.close()
    except KeyError as e:
        cur.close()
        return internal_error(f"KeyError: {str(e)}")
    except Exception as e:
        cur.close()
        return internal_error(f"Unknown Exception: {str(e)}")
    return json.dumps({"status": 200})


@app.route('/get_results', methods=['POST'])
def get_results():
    try:
        cur = conn.cursor()
        r = request.get_json()
        scan_id = r['scan_id']

        cur.execute(f"""
            SELECT scan.id, scan.arguments, scan.cidr, scan.created_at, result.ip_address, 
            result.hostnames, result.status, result.status_reason, result.tcp, result.tcp 
            FROM scan INNER JOIN result ON scan.id=result.scan_id
            WHERE scan.id='{scan_id}';
        """)
        rows = cur.fetchall()
        scan_results = []
        for row in rows:
            scan_results.append({
                "scan_id": row[0],
                "scan_arguments": row[1],
                "scan_cidr": row[2],
                "scan_created": row[3].isoformat(),
                "host_ip": row[4],
                "hostnames": row[5],
                "host_status": row[6],
                "host_status_reason": row[7],
                "host_tcp": row[8],
                "host_udp": row[9]
            })
        conn.commit()
        cur.close()
    except KeyError as e:
        cur.close()
        return internal_error(f"KeyError: {str(e)}")
    except Exception as e:
        cur.close()
        return internal_error(f"Unknown Exception: {str(e)}")
    return json.dumps(scan_results)


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
    return resp


try:
    params = config()
    # connect to the PostgreSQL server
    conn = psycopg2.connect(**params)
    create_tables()
except Exception as e:
    print(str(e))

if __name__ == '__main__':
    app.run(host='0.0.0.0')
    atexit.register(cur.close)
    atexit.register(conn.close)
