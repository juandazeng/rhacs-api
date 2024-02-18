import csv
import argparse
import json
import ssl
import re
from urllib.request import urlopen, Request
from pathlib import Path

# Constants
UBI_IDENTIFIER_IN_LABEL = "\"url\"=\"https://access.redhat.com/containers/#/registry.access.redhat.com/ubi"
OS_ID_RHEL = "rhel"
UBI_REGEX = r"(https\://.+/([^/]+)/images/(\d[\d.]*)\-(\d[\d.]*))"
CSV_HEADER = ["Cluster", "Namespace", "Deployment", "Image", "OS", "OS Image Name", "OS Image Version", "OS Image Release"]
IS_EXCLUDE_OPENSHIFT_NAMESPACE = True

# Prepare for API calls
rhacsApiUrl = None
rhacsApiToken = None
csvFileName = None
authorizationHeader = None
requestContext = ssl.create_default_context()
requestContext.check_hostname = False
requestContext.verify_mode = ssl.CERT_NONE

# Main function
def main():
    # We will modify these global variables
    global rhacsApiUrl, rhacsApiToken, csvFileName, authorizationHeader
    
    # Initialize arguments parser
    parser = argparse.ArgumentParser()

    parser.add_argument("-u", "--url", help="RHACS API URL, e.g. https://central-stackrox.apps.myocpcluster.com/v1", required=True)
    parser.add_argument("-t", "--token", help="RHACS API token", required=True)
    parser.add_argument("-o", "--output", help="Output CSV file name", required=True)
    arguments = parser.parse_args()
    
    rhacsApiUrl = arguments.url
    rhacsApiToken = arguments.token
    csvFileName = arguments.output

    # Prepare for API calls
    authorizationHeader = {
        "Authorization": "Bearer " + rhacsApiToken,
        "Accept": "application/json"
    }

    responseJson = getJsonFromRhacsApi("/deployments")
    if responseJson is not None:
        # Create the CSV file
        with open(csvFileName, "w", newline="") as f:
            writer = csv.writer(f, dialect="excel")
            writer.writerow(CSV_HEADER)

            # Process all deployments across all clusters
            deployments = responseJson["deployments"]

            # Skip all openshift namespaces is IS_EXCLUDE_OPENSHIFT_NAMESPACE is True
            deploymentsToBeInspected = [deployment for deployment in deployments if not deployment["namespace"].startswith("openshift")] if IS_EXCLUDE_OPENSHIFT_NAMESPACE else deployments

            deploymentCount = len(deploymentsToBeInspected)
            currentDeploymentIndex = 0
            for deployment in deploymentsToBeInspected:
                cluster = deployment["cluster"]
                namespace = deployment["namespace"]
                deploymentId = deployment["id"]
                deploymentName = deployment["name"]

                # Get the deployment detail
                currentDeploymentIndex += 1
                print(f"{currentDeploymentIndex} of {deploymentCount} - Inspecting {cluster}/{namespace}/{deploymentName}...")
                responseJson = getJsonFromRhacsApi("/deployments/" + deploymentId)
                if responseJson is not None:
                    containers = responseJson["containers"]
                    for container in containers:
                        imageId = container["image"]["id"]
                        
                        # Get the image detail
                        responseJson = getJsonFromRhacsApi("/images/" + imageId)
                        if responseJson is not None:
                            imageFullName = responseJson["name"]["fullName"]
                            os = responseJson["scan"]["operatingSystem"]
                            ubiName = ""
                            ubiVersion = ""
                            ubiRelease = ""

                            # Get more details if it's a rhel-based image
                            if os.startswith(OS_ID_RHEL):
                                for layer in responseJson["metadata"]["v1"]["layers"]:
                                    if layer["instruction"] == "LABEL":
                                        value = layer["value"]
                                        # UBI-specific metadata checking
                                        if UBI_IDENTIFIER_IN_LABEL in value:
                                            regexResult = re.search(UBI_REGEX, value)
                                            if regexResult is not None:
                                                ubiName = regexResult.group(2)
                                                ubiVersion = regexResult.group(3)
                                                ubiRelease = regexResult.group(4)
                                                # Exit the current loop
                                                break

                                # If the base image labels have been removed,
                                # try to get the metadata from the url
                                if ubiName == "":
                                    labels = responseJson["metadata"]["v1"]["labels"]
                                    if hasattr(labels, "url"):
                                        regexResult = re.search(UBI_REGEX, labels["url"])
                                        if regexResult is not None:
                                            ubiName = regexResult.group(2)
                                            ubiVersion = regexResult.group(3)
                                            ubiRelease = regexResult.group(4)
                                    
                                    # If that failed, try to get the metadata from the labels
                                    if ubiName == "":
                                        ubiName = labels["name"]
                                        ubiVersion = labels["version"]
                                        ubiRelease = labels["release"]

                            # Write the image detail into the CSV file
                            writer.writerow([
                                cluster,
                                namespace,
                                deploymentName,
                                imageFullName,
                                os,
                                ubiName,
                                ubiVersion,
                                ubiRelease
                            ])
                            f.flush()

        print(f"Successfully generated {csvFileName}\n")
                    
def getJsonFromRhacsApi(requestPath):
    url=rhacsApiUrl + requestPath
    with urlopen(Request(
        url=url,
        headers=authorizationHeader),
        context=requestContext) as response:
        if response.status != 200:
            print(f"Error: {response.status} - {response.msg} for request:{url}")
            return None
        else:
            return json.loads(response.read())
        
if __name__=="__main__": 
    main() 