#!/usr/bin/env python3

import argparse

import docker
import yaml
from halo import Halo


def checkImage(client, dict):

    if 'image' in dict:
        spinner = Halo(text='Checking: ' + dict['image'], spinner='dots')
        spinner.start()
        image = client.api.inspect_distribution(dict['image'])
        spinner.stop()

        ref = dict['image'].split(':')[0] + '@' + image['Descriptor']['digest']

        print("Updated: ", dict['image'], " -> ", ref)
        dict['image'] = ref


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="""
    Convert compose images references to full sha digests
    """)
    parser.add_argument("--file",
                        default="./docker-compose.yml",
                        help="Compose File Input (default: %(default)s)")
    parser.add_argument("--outfile",
                        default="./dab.yml",
                        help="Compose File Output (default: %(default)s)")

    args = parser.parse_args()

    client = docker.from_env()

    with open(args.file) as file:
        compose = yaml.full_load(file)

        for item, doc in compose['services'].items():
            checkImage(client, compose['services'][item])

        yaml.dump(compose)

    with open(args.outfile, 'w') as file:
        documents = yaml.dump(compose, file)
