import os
import site
import shutil
import urllib
import argparse

FILES = map(lambda a: '{}.py'.format(a), ['__init__', 'inet', 'l2', 'yore_fields'])
DOWNLOAD_URL = 'https://raw.githubusercontent.com/gvahim/scapy-yore/master/scapy_changes_only/yore/{}'


def download():
    directory_ = 'temp'
    if not os.path.exists(directory_):
        os.mkdir(directory_)

    for file_ in FILES:
        url = DOWNLOAD_URL.format(file_)
        print 'Downloading {} from {}...'.format(file_, url)
        save_path = os.path.join(directory_, file_)
        urllib.urlretrieve(url, save_path)
    return directory_


def main(should_download):
    directory = 'yore'
    if should_download:
        directory = download()
    path = [p for p in site.getsitepackages() if 'site-packages' in p][0]
    installation_path = os.path.join(path, 'scapy', 'layers', 'yore')
    shutil.copytree(directory, installation_path)
    config_path = os.path.join(path, 'scapy', 'config.py')
    with open(config_path, 'a') as config:
        config.write("conf.load_layers.append('yore')")
        config.write(os.linesep)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--download', action='store_true', help='download the files from github')

    args = parser.parse_args()

    main(args.download)
