import machine
import binascii
import hashlib
import os
import requests
import logging

def check_version(host, project, auth=None, timeout=5) -> (bool, str):
    current_version = ''
    try:
        if 'version' in os.listdir():
            with open('version', 'r') as current_version_file:
                current_version = current_version_file.readline().strip()

        if auth:
            response = requests.get(f'{host}/{project}/version', headers={'Authorization': f'Basic {auth}'}, timeout=timeout)
        else:
            response = requests.get(f'{host}/{project}/version', timeout=timeout)
        response_status_code = response.status_code
        response_text = response.text
        response.close()
        if response_status_code != 200:
            logging.warning('Remote version file %s/%s/ version not found', host,project)
            return False, current_version
        remote_version = response_text.strip()
        return current_version != remote_version, remote_version
    except Exception as ex:
        logging.error('Something went wrong: %s', ex)
        return False, current_version

def fetch_manifest(host, project, remote_version, prefix_or_path_separator, auth=None, timeout=5):
    if auth:
        response = requests.get(f'{host}/{project}/{remote_version}{prefix_or_path_separator}manifest', headers={'Authorization': f'Basic {auth}'}, timeout=timeout)
    else:
        response = requests.get(f'{host}/{project}/{remote_version}{prefix_or_path_separator}manifest', timeout=timeout)
    response_status_code = response.status_code
    response_text = response.text
    response.close()
    if response_status_code != 200:
        logging.error('Remote manifest file %s/%s/%s%s manifest not found',
                      host,project,remote_version,prefix_or_path_separator)
        raise Exception(f"Missing manifest for {remote_version}")
    return process_manifet(response=response_text)

def process_manifet(response):
    '''
        Processes a manifest file into an array of dictionary valuses for a file/sha256 hash
        e.g. 
            [{"file":"test.py", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
             {"file":"random.py", "sha256": "648fec30f74b77e2c02bb810129ecf9204ed5c3715fde2111ee4ad756f12e3b6"},]
    '''
    lines = response.splitlines()
    manifest = []
    for line in lines:
        if line is not "":
            file_details = line.split(' ')
            if len(file_details) == 2:
                file = file_details[0]
                file_hash = file_details[1]
                manifest.append({'file': file, "sha256": file_hash})
            else:
                file = file_details[0]
                manifest.append({'file': file})
    return manifest

def generate_auth(user=None, passwd=None) -> str | None:
    if not user and not passwd:
        return None
    if (user and not passwd) or (passwd and not user):
        raise ValueError('Either only user or pass given. None or both are required.')
    auth_bytes = binascii.b2a_base64(f'{user}:{passwd}'.encode())
    return auth_bytes.decode().strip()

def get_sha256_hash_file(filename, buffer_size=2**10*8):
    file_hash = hashlib.sha256()
    with open(filename, mode="rb") as f:
        while chunk := f.read(buffer_size):
            file_hash.update(chunk)
    return binascii.hexlify(file_hash.digest()).decode('utf-8')

def ota_update(host, project, filenames=None, use_version_prefix=True, user=None, passwd=None, hard_reset_device=True, soft_reset_device=False, timeout=5) -> None:
    all_files_found = True
    auth = generate_auth(user, passwd)
    prefix_or_path_separator = '_' if use_version_prefix else '/'
    try:
        version_changed, remote_version = check_version(host, project, auth=auth, timeout=timeout)
        if version_changed:
            try:
                os.mkdir('tmp')
            except OSError as e:
                if e.errno != 17:
                    raise
            if filenames is None:
                filenames = fetch_manifest(host, project, remote_version, prefix_or_path_separator, auth=auth, timeout=timeout)
            for filename in filenames:
                if filename["file"].endswith('/'):
                    dir_path="tmp"
                    for dir in filename["file"].split('/'):
                        if len(dir) > 0:
                            built_path=f"{dir_path}/{dir}"
                            dir_path = built_path
                            try:
                                os.mkdir(built_path)
                            except OSError as e:
                                if e.errno != 17:
                                    raise
                    continue
                if auth:
                    response = requests.get(f'{host}/{project}/{remote_version}{prefix_or_path_separator}{filename["file"]}', headers={'Authorization': f'Basic {auth}'}, timeout=timeout)
                else:
                    response = requests.get(f'{host}/{project}/{remote_version}{prefix_or_path_separator}{filename["file"]}', timeout=timeout)
                response_status_code = response.status_code
                response_content = response.content
                response.close()
                if response_status_code != 200:
                    logging.error('Remote source file %s/%s/%s%s%s not found',
                                  host,project,remote_version,prefix_or_path_separator,filename["file"])
                    all_files_found = False
                    continue
                if filename['sha256'] == binascii.hexlify(hashlib.sha256(response_content).digest()).decode('utf-8'):
                    with open(f'tmp/{filename["file"]}', 'wb') as source_file:
                        source_file.write(response_content)
                else:
                    logging.error("File %s hash does not match so aborting the update", filename['file'])
                    all_files_found = False
                    continue
            if all_files_found:
                dirs=[]
                for filename in filenames:
                    if filename["file"].endswith('/'):
                        dir_path=""
                        for dir in filename["file"].split('/'):
                            if len(dir) > 0:
                                built_path=f"{dir_path}/{dir}"
                                dir_path = built_path
                                try:
                                    os.mkdir(built_path)
                                except OSError as e:
                                    if e.errno != 17:
                                        raise
                                dirs.append(f"tmp/{built_path}")
                        continue
                    with open(f'tmp/{filename["file"]}', 'rb') as source_file, open(filename["file"], 'wb') as target_file:
                        target_file.write(source_file.read())
                    os.remove(f'tmp/{filename["file"]}')
                try:
                    while len(dirs) > 0:
                        os.rmdir(dirs.pop())
                    os.rmdir('tmp')
                except:
                    pass
                with open('version', 'w', encoding='utf-8') as current_version_file:
                    current_version_file.write(remote_version)
                if soft_reset_device:
                    logging.warning('Soft-resetting device...')
                    machine.soft_reset()
                if hard_reset_device:
                    logging.warning('Hard-resetting device...')
                    machine.reset()
    except Exception as ex:
        logging.error('Something went wrong: %s', ex)
        raise ex


def check_for_ota_update(host, project, user=None, passwd=None, timeout=5, soft_reset_device=False):
    auth = generate_auth(user, passwd)
    version_changed, remote_version = check_version(host, project, auth=auth, timeout=timeout)
    if version_changed:
        if soft_reset_device:
            logging.warning('Found new version %s, soft-resetting device...', remote_version)
            machine.soft_reset()
        else:
            logging.warning('Found new version %s, hard-resetting device...', remote_version)
            machine.reset()
