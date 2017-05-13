import os
import site
import shutil
import urllib
import argparse

FILES = map(lambda a: '{}.py'.format(a), ['__init__', 'inet', 'l2', 'yore_fields'])
DOWNLOAD_URL = 'https://raw.githubusercontent.com/gvahim/scapy-yore/master/scapy_changes_only/yore/{}'

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--download', action='store_true', help='download the files from github')

    args = parser.parse_args()

    directory = 'yore'
    if args.download:
        directory = 'temp'
        if not os.path.exists(directory):
            os.mkdir(directory)

        for file_ in FILES:
            url = DOWNLOAD_URL.format(file_)
            print 'Downloading {} from {}...'.format(file_, url)
            save_path = os.path.join(directory, file_)
            urllib.urlretrieve(url, save_path)

    path = [p for p in site.getsitepackages() if 'site-packages' in p][0]
    installation_path = os.path.join(path, 'scapy', 'layers', 'yore')
    shutil.copytree(directory, installation_path)

    config_path = os.path.join(path, 'scapy', 'config.py')
    with open(config_path, 'a') as config:
        config.write("conf.load_layers.append('yore')")
        config.write(os.linesep)
