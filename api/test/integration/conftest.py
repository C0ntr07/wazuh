import json
import os
import re
import shutil
import subprocess
import time
from base64 import b64encode

import pytest
import requests
import urllib3
import yaml

current_path = os.path.dirname(os.path.abspath(__file__))

with open('common.yaml', 'r') as stream:
    common = yaml.safe_load(stream)['variables']
login_url = f"{common['protocol']}://{common['host']}:{common['port']}/{common['version']}{common['login_endpoint']}"
basic_auth = f"{common['user']}:{common['pass']}".encode()
login_headers = {'Content-Type': 'application/json',
                 'Authorization': f'Basic {b64encode(basic_auth).decode()}'}


def get_token_login_api():
    """Get the API token for the test

    Returns
    -------
    str
        API token
    """
    response = requests.get(login_url, headers=login_headers, verify=False)
    if response.status_code == 200:
        return json.loads(response.content.decode())['token']
    else:
        raise Exception(f"Error obtaining login token: {response.json()}")


def pytest_tavern_beta_before_every_test_run(test_dict, variables):
    """Disable HTTPS verification warnings."""
    urllib3.disable_warnings()
    variables["test_login_token"] = get_token_login_api()


def build_and_up(interval: int = 10):
    """Build all Docker environments needed for the current test.

    Parameters
    ----------
    interval : int
        Time interval between every healthcheck

    Returns
    -------
    dict
        Dict with healthchecks parameters
    """
    pwd = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'env')
    os.chdir(pwd)
    values = {
        'interval': interval,
        'max_retries': 30,
        'retries': 0
    }
    current_process = subprocess.Popen(["docker-compose", "build"])
    current_process.wait()
    current_process = subprocess.Popen(["docker-compose", "up", "-d"])
    current_process.wait()

    return values


def down_env():
    """Stop all Docker environments for the current test."""
    pwd = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'env')
    os.chdir(pwd)
    current_process = subprocess.Popen(["docker-compose", "down", "-t", "0"])
    current_process.wait()


def check_health(interval: int = 10, node_type: str = 'manager', agents: list = None):
    """Check the Wazuh nodes health.

    Parameters
    ----------
    interval : int
        Time interval between every healthcheck
    node_type : str
        Can be agent or manager
    agents :
        List of active agents for the current test
        (only needed if the agents needs a custom healthcheck)

    Returns
    -------
    bool
        True if all healthchecks pass, False if not
    """
    time.sleep(interval)
    if node_type == 'manager':
        health = subprocess.check_output(
            "docker inspect env_wazuh-master_1 -f '{{json .State.Health.Status}}'", shell=True)
        return False if not health.startswith(b'"healthy"') else True
    elif node_type == 'agent':
        for agent in agents:
            health = subprocess.check_output(
                f"docker inspect env_wazuh-agent{agent}_1 -f '{{{{json .State.Health.Status}}}}'", shell=True)
            if not health.startswith(b'"healthy"'):
                return False
        return True


def create_tmp_folders():
    """Create basic temporal structure for integration tests."""
    os.makedirs(os.path.join(current_path, 'env', 'configurations', 'tmp', 'manager'), exist_ok=True)
    os.makedirs(os.path.join(current_path, 'env', 'configurations', 'tmp', 'agent'), exist_ok=True)


def general_procedure(module: str):
    """Copy the configurations files of the specified module to temporal folder.
    The temporal folder will be processed in the environments's entrypoints

    Parameters
    ----------
    module : str
        Name of the tested module
    """
    folder_content = os.path.join(current_path, 'env', 'configurations', module, '*')
    tmp_content = os.path.join(current_path, 'env', 'configurations', 'tmp')
    os.makedirs(tmp_content, exist_ok=True)
    os.popen(f'cp -rf {folder_content} {tmp_content}')
    healthcheck_procedure(module)


def healthcheck_procedure(module: str):
    """Copy base healthchecks for managers and agents.
    If the environment need a specific one, the base healthcheck will be replaced.

    Parameters
    ----------
    module : str
        Name of the tested module
    """
    manager_folder = os.path.join(current_path, 'env', 'configurations', module, 'manager', 'healthcheck')
    agent_folder = os.path.join(current_path, 'env', 'configurations', module, 'agent', 'healthcheck')
    master_base_folder = os.path.join(current_path, 'env', 'configurations', 'base', 'manager', 'healthcheck')
    agent_base_folder = os.path.join(current_path, 'env', 'configurations', 'base', 'agent', 'healthcheck')
    tmp_content = os.path.join(current_path, 'env', 'configurations', 'tmp')

    os.popen(f'cp -rf {master_base_folder} {os.path.join(tmp_content, "manager")}')
    os.popen(f'cp -rf {agent_base_folder} {os.path.join(tmp_content, "agent")}')
    if os.path.exists(manager_folder):
        os.popen(f'cp -rf {manager_folder} {os.path.join(tmp_content, "manager")}')
    elif os.path.exists(agent_folder):
        os.popen(f'cp -rf {agent_folder} {os.path.join(tmp_content, "agent")}')


def change_rbac_mode(rbac_mode: str):
    """Modify security.yaml in base folder to change RBAC mode for the current test.

    Parameters
    ----------
    rbac_mode : str
        RBAC Mode: Black (by default: all allowed), White (by default: all denied)
    """
    with open(os.path.join(current_path, 'env', 'configurations', 'base', 'manager', 'security.yaml'),
              'r+') as rbac_conf:
        content = rbac_conf.read()
        rbac_conf.seek(0)
        rbac_conf.write(re.sub(r'rbac_mode: (white|black)', f'rbac_mode: {rbac_mode}', content))


def clean_tmp_folder():
    """Remove temporal folder used te configure the environment and set RBAC mode to Black.
    """
    with open(os.path.join(current_path, 'env', 'configurations', 'base', 'manager', 'security.yaml'),
              'r+') as rbac_conf:
        content = rbac_conf.read()
        rbac_conf.seek(0)
        rbac_conf.write(re.sub(r'rbac_mode: (white|black)', f'rbac_mode: black', content))

    shutil.rmtree(os.path.join(current_path, 'env', 'configurations', 'tmp'), ignore_errors=True)


def generate_rbac_pair(index: int, permission: dict):
    """Generate a policy and the relationship between it and the testing role.

    Parameters
    ----------
    index : int
        Integer that is used to define a policy and a relationship id that are not used in the database
    permission : dict
        Dict containing the policy information

    Returns
    -------
    list
        List with two SQL sentences, the first creates the policy and the second links it with the testing role
    """
    role_policy_pair = [
        f'INSERT INTO policies VALUES({99 + index},\'testing{index}\',\'{json.dumps(permission)}\','
        f'\'1970-01-01 00:00:00\');\n',
        f'INSERT INTO roles_policies VALUES({99 + index},99,{99 + index},{index},\'1970-01-01 00:00:00\');\n'
    ]

    return role_policy_pair


def rbac_custom_config_generator(module: str, rbac_mode: str):
    """Create a custom SQL script for RBAC integrated tests.
    This is achieved by reading the permissions information in the RBAC folder of the specific module.

    Parameters
    ----------
    module : str
        Name of the tested module
    rbac_mode : str
        RBAC Mode: Black (by default: all allowed), White (by default: all denied)
    """
    custom_rbac_path = os.path.join(current_path, 'env', 'configurations', 'tmp', 'manager', 'custom_rbac_schema.sql')

    try:
        with open(os.path.join(current_path, 'env', 'configurations', 'rbac', module,
                               f'{rbac_mode}_config.yaml')) as configuration_sentences:
            list_custom_policy = yaml.safe_load(configuration_sentences.read())
    except FileNotFoundError:
        return

    sql_sentences = list()
    sql_sentences.append('PRAGMA foreign_keys=OFF;\n')
    sql_sentences.append('BEGIN TRANSACTION;\n')
    sql_sentences.append('DELETE FROM roles_policies WHERE role_id=99;\n')
    for index, permission in enumerate(list_custom_policy):
        sql_sentences.extend(generate_rbac_pair(index, permission))
    sql_sentences.append('COMMIT')

    os.makedirs(os.path.dirname(custom_rbac_path), exist_ok=True)
    with open(custom_rbac_path, 'w') as rbac_config:
        rbac_config.writelines(sql_sentences)


@pytest.fixture(scope='session', autouse=True)
def api_test(request):
    """This function is responsible for setting up the Docker environment necessary for every test.
    This function will be executed with all the integrated API tests.

    Parameters
    ----------
    request : pytest.fixtures.SubRequest
        Object that contains information about the current test
    """
    test_filename = request.node.config.args[0].split('_')
    if 'rbac' in test_filename:
        rbac_mode = test_filename[2]
        module = test_filename[3]
    else:
        rbac_mode = None
        module = test_filename[1]
    create_tmp_folders()
    general_procedure(module)
    if rbac_mode:
        change_rbac_mode(rbac_mode)
        rbac_custom_config_generator(module, rbac_mode)

    values = build_and_up(interval=10)
    while values['retries'] < values['max_retries']:
        managers_health = check_health(interval=values['interval'])
        agents_health = check_health(interval=values['interval'], node_type='agent', agents=range(1, 9))
        if managers_health and agents_health:
            time.sleep(values['interval'])
            yield
            break
        else:
            values['retries'] += 1
    clean_tmp_folder()
    down_env()