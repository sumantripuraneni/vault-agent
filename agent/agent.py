import requests
import json
import os
import logging
import sys
import yaml
import filecmp
import time
import shutil
import logo


# Function to read the environment parameters and create config dict
def getConfig():

    config = {}
    try:
        config["HASHI_VAULT_URL"] = os.environ["HASHI_VAULT_URL"]
        config["MOUNT_PATH_TO_WRITE_SECRETS"] = os.environ[
            "MOUNT_PATH_TO_WRITE_SECRETS"
        ]
        config["VAULT_SECRETS_REFRESH_SECONDS"] = os.environ[
            "VAULT_SECRETS_REFRESH_SECONDS"
        ]
        config["SECRETS_CONFIGMAP_FILE"] = os.environ["SECRETS_CONFIGMAP_FILE"]
    except KeyError as key:
        log.error("Environment Variable {} not found".format(key))
        sys.exit(1)

    # Add trailing '/' is doesn't exist,
    # this helps in path formations later in the code below
    if not config["HASHI_VAULT_URL"].endswith("/"):
        config["HASHI_VAULT_URL"] = config["HASHI_VAULT_URL"] + "/"

    if not config["MOUNT_PATH_TO_WRITE_SECRETS"].endswith("/"):
        config["MOUNT_PATH_TO_WRITE_SECRETS"] = (
            config["MOUNT_PATH_TO_WRITE_SECRETS"] + "/"
        )

    return config


# Function to read the service account token
def getSAToken():

    tokenFile = open("/var/run/secrets/kubernetes.io/serviceaccount/token", "r")
    saToken = tokenFile.read().replace("\n", "")
    tokenFile.close()

    return saToken


# Function to get the KubeAuthToken from HashiVault
def getKubeHvaultAuthToken(role_name, saToken):

    authTokenUrl = config["HASHI_VAULT_URL"] + "v1/auth/kubernetes/login"
    try:
        resp = requests.post(authTokenUrl, data={"jwt": saToken, "role": role_name})
        resp.raise_for_status()
    except requests.exceptions.HTTPError as e:
        log.error(
            "Error retriving Kubernetes Auth Token from Hashi Vault: {}".format(e)
        )
        log.error(resp.json())
        sys.exit(1)

    return resp.json().get("auth").get("client_token")


# Function to read the secrets from HashiVault path
def getSecretFromHvault(secret_path, k8HvaultToken):

    secretRetrivalurl = config["HASHI_VAULT_URL"] + secret_path
    headers = {"X-Vault-Token": k8HvaultToken}
    try:
        resp = requests.get(secretRetrivalurl, headers=headers)
        resp.raise_for_status()
    except requests.exceptions.HTTPError as e:
        log.error("Error retriving secret from Hashi Vault: {}".format(e))

    # secretFromHvault=resp.json().get('data')
    return resp.json().get("data")


# Function to read the configuration values from OpenShift ConfigMap
# ConfigMap contains array of -
# vault_secret_path - Hashi corp vault path
# to_file_name - file name to write the secrets recieved from Hvault vault_secret_path
def readFromSecretsConfigMap():

    try:
        with open(config["SECRETS_CONFIGMAP_FILE"], "r") as file:
            return yaml.full_load(file)
    except (OSError, IOError) as e:
        log.error("Error reading from file: {}".format(e))
        sys.exit(1)
    except yaml.YAMLError as e:
        log.error("Error while loading yaml file: {}".format(e))
        sys.exit(1)


if __name__ == "__main__":

    # Log setting
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        stream=sys.stdout, format="[%(asctime)s] [%(levelname)s] - %(message)s"
    )
    log = logging.getLogger()
    level = logging.getLevelName(log_level)
    log.setLevel(log_level)

    # Print ASCII Art Banner
    print(logo.logo)

    # Print effective log level
    log.info("Log Level: {}".format(logging.getLevelName(log.getEffectiveLevel())))

    log.info("Loading configuration from environment variables")

    # Load configurations from environment
    config = getConfig()

    log.info("Hashi vault server: " + config["HASHI_VAULT_URL"])

    # Call function to get service account token
    log.info("Get the OpenShift service account token")

    saToken = getSAToken()

    log.debug("OpenShift Service Account Token: " + saToken)

    while True:

        log.info("Read the vault secrets configmap")

        vault_configmap_contents = readFromSecretsConfigMap()

        # Call function to get KubeAuth token and 
        # pass the role name and saToken as a function argument
        log.info("Get the Kubernetes auth token from vault")

        k8HvaultToken = getKubeHvaultAuthToken(
            vault_configmap_contents["vault_kube_auth_role_name"], saToken
        )

        log.debug("Hashicorp Vault Kube Auth Token: " + k8HvaultToken)

        for i_secret in vault_configmap_contents["secrets"]:

            # Call function to retrieve secrets from vault
            log.info(
                "Retrieve secret from vault path: {}".format(
                    i_secret["vault_secret_path"]
                )
            )

            secretFromHvault = getSecretFromHvault(
                i_secret["vault_secret_path"], k8HvaultToken
            )

            log.debug("Secret from Hashi Vault: " + str(secretFromHvault))

            temp_secrets_file = "/tmp/" + i_secret["to_file_name"]
            actual_secrets_file = (
                config["MOUNT_PATH_TO_WRITE_SECRETS"] + i_secret["to_file_name"]
            )

            if secretFromHvault:

                if os.path.exists(actual_secrets_file):

                    log.info("Write secret to temp path: {}".format(temp_secrets_file))
                    json.dump(secretFromHvault, open(temp_secrets_file, "w"))
                    log.info(
                        "Compare two secrets {} and {}".format(
                            temp_secrets_file, actual_secrets_file
                        )
                    )

                    if not filecmp.cmp(
                        temp_secrets_file, actual_secrets_file, shallow=False
                    ):

                        log.info(
                            "Secrets are different!!, so render new secret to file: {}".format(
                                actual_secrets_file
                            )
                        )
                        shutil.move(temp_secrets_file, actual_secrets_file)

                    else:

                        log.info(
                            "Two secrets from {} and {} are same. So skipping creating again".format(
                                temp_secrets_file, actual_secrets_file
                            )
                        )
                        log.info(
                            "Delete temp file created: {}".format(temp_secrets_file)
                        )
                        os.remove(temp_secrets_file)

                else:

                    log.info("Write secret to {}".format(actual_secrets_file))
                    json.dump(secretFromHvault, open(actual_secrets_file, "w"))

            else:

                log.warning(
                    "No data retrieved for Path: {} and not creating file: {}".format(
                        i_secret["vault_secret_path"], actual_secrets_file
                    )
                )

        log.info(
            "Waiting for {} seconds before connecting to vault".format(
                config["VAULT_SECRETS_REFRESH_SECONDS"]
            )
        )

        time.sleep(int(config["VAULT_SECRETS_REFRESH_SECONDS"]))
