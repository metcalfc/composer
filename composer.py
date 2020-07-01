#!/usr/bin/env python3

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

import docker
import github3
import yaml
from flask import Flask, redirect, request, session, url_for
from flask.json import jsonify
from halo import Halo
from requests_oauthlib import OAuth2Session

app = Flask(__name__)


# This information is obtained upon registration of a new GitHub
client_id = "51187c529dd6739844cc"
client_secret = "8ba64c6a81d7dc707a604077c5910c357951205c"
authorization_base_url = "https://github.com/login/oauth/authorize"
token_url = "https://github.com/login/oauth/access_token"

CRED_DIR = str(Path.home()) + "/.config/composer"
CRED_FILE = CRED_DIR + "/config.yml"
if not os.path.exists(CRED_DIR):
    os.makedirs(CRED_DIR)


@app.route("/")
def demo():
    """Step 1: User Authorization.

    Redirect the user/resource owner to the OAuth provider (i.e. Github)
    using an URL with a few key OAuth parameters.
    """
    scopes = ["read:user", "gist"]
    github = OAuth2Session(client_id, scope=scopes)
    authorization_url, state = github.authorization_url(authorization_base_url)

    # State is used to prevent CSRF, keep this for later.
    session["oauth_state"] = state
    return redirect(authorization_url)


# Step 2: User authorization, this happens on the provider.


@app.route("/callback", methods=["GET"])
def callback():
    """ Step 3: Retrieving an access token.

    The user has been redirected back from the provider to your registered
    callback URL. With this redirection comes an authorization code included
    in the redirect URL. We will use that to obtain an access token.
    """

    github = OAuth2Session(client_id, state=session["oauth_state"])
    token = github.fetch_token(
        token_url, client_secret=client_secret, authorization_response=request.url,
    )

    # At this point you can fetch protected resources but lets save
    # the token and show how this is done from a persisted token
    # in /profile.
    session["oauth_token"] = token

    return redirect(url_for(".profile"))


@app.route("/profile", methods=["GET"])
def profile():
    """Fetching a protected resource using an OAuth 2 token.
    """
    github = OAuth2Session(client_id, token=session["oauth_token"])
    user = github.get("https://api.github.com/user").json()

    data = {}
    data["token"] = session["oauth_token"]["access_token"]
    data["login"] = user["login"]

    with open(CRED_FILE, "w") as fd:
        yaml.dump(data, fd)

    return redirect(url_for(".shutdown"))


def shutdown_server():
    func = request.environ.get("werkzeug.server.shutdown")
    if func is None:
        raise RuntimeError("Not running with the Werkzeug Server")
    func()


@app.route("/shutdown", methods=["GET"])
def shutdown():
    shutdown_server()
    return "GitHub Credentials Stored. Close this tab."


def do_gh_login():
    url = "http://localhost:5000"
    print(
        "\n\n\n\nPlease open a browser on: "
        + url
        + " to setup your GitHub credentials.\n\n\n\n"
    )

    app.secret_key = os.urandom(24)
    app.run(debug=False, host="0.0.0.0")


def check_gh_token(file):
    token = id = ""

    try:
        with open(file, "r") as fd:
            data = yaml.full_load(fd)
    except FileNotFoundError as e:
        return None

    gh = github3.login(token=data["token"])

    return gh


def check_image(client, dict):

    if "image" in dict:
        spinner = Halo(text="Checking: " + dict["image"], spinner="dots")
        spinner.start()
        image = client.api.inspect_distribution(dict["image"])
        spinner.stop()

        ref = dict["image"].split(":")[0] + "@" + image["Descriptor"]["digest"]

        print("Updated: ", dict["image"], " -> ", ref)
        dict["image"] = ref


def compile_compose_file(compose_file, out_file):
    client = docker.from_env()

    with open(compose_file) as file:
        compose = yaml.full_load(file)

        for item, doc in compose["services"].items():
            check_image(client, compose["services"][item])

    with open(out_file, "w") as file:
        yaml.dump(compose, file)


if __name__ == "__main__":
    # This allows us to use a plain HTTP callback
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

    parser = argparse.ArgumentParser(
        description="""
    Convert compose images references to full sha digests
    """
    )
    parser.add_argument(
        "--file",
        default="./docker-compose.yml",
        help="Compose File Input (default: %(default)s)",
    )
    parser.add_argument(
        "--outfile",
        default="./dab.yml",
        help="Compose File Output (default: %(default)s)",
    )

    args = parser.parse_args()

    gh = check_gh_token(CRED_FILE)

    if gh is None:
        do_gh_login()

    compile_compose_file(args.file, args.outfile)
