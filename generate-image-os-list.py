import csv
import argparse
import json
import ssl
import re
from urllib.request import urlopen, Request
from datetime import datetime

# Constants
UBI_IDENTIFIER_IN_LABEL = "\"url\"=\"https://access.redhat.com/containers/#/registry.access.redhat.com/ubi"
OS_ID_RHEL = "rhel"
UBI_PREFIX = "ubi"
UBI_REGEX = r"(?:https\://.+/([^/]+)/images/(\d[\d.]*)\-(\d[\d.]*))"
DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S %z"
CSV_HEADER = [
    "Cluster Name",
    "Environment",
    "Cluster Descriptor",
    "Namespace",
    "Application Code",
    "Deployment",
    "Image",
    "Created On",
    "OS",
    "UBI Name",
    "UBI Version",
    "UBI Release"
]
IS_INCLUDE_OPENSHIFT_NAMESPACE = False

# The cluster regex matches the following:
# ocps4 - uat_abc_def123 <-- cluster name: ocps4, environment: uat, cluster descriptor: abc_def123
# ocps4 - uat            <-- cluster name: ocps4, environment: uat
# ocps4                  <-- cluster name: ocps4
CLUSTER_INFO_REGEX = r"([^\W_]+)(?:[\W_]+([^\W_]+)(?:[\W_]+(.*))?)?$"

# Prepare for API calls
rhacsCentralUrl = None
rhacsApiToken = None
csvFileName = None
authorizationHeader = None
requestContext = ssl.create_default_context()
requestContext.check_hostname = False
requestContext.verify_mode = ssl.CERT_NONE

# Main function
def main():
    # We will modify these global variables
    global rhacsCentralUrl, rhacsApiToken, csvFileName, authorizationHeader
    
    # Initialize arguments parser
    parser = argparse.ArgumentParser()

    parser.add_argument("-u", "--url", help="RHACS Central URL, e.g. https://central-stackrox.apps.myocpcluster.com", required=True)
    parser.add_argument("-t", "--token", help="RHACS API token", required=True)
    parser.add_argument("-o", "--output", help="Output CSV file name", required=True)
    arguments = parser.parse_args()
    
    rhacsCentralUrl = arguments.url
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

            # Skip all openshift namespaces unless IS_INCLUDE_OPENSHIFT_NAMESPACE is True
            deploymentsToBeInspected = deployments if IS_INCLUDE_OPENSHIFT_NAMESPACE else [deployment for deployment in deployments if not deployment["namespace"].startswith("openshift")] 

            deploymentCount = len(deploymentsToBeInspected)
            currentDeploymentIndex = 0
            for deployment in deploymentsToBeInspected:
                clusterName = deployment["cluster"]
                clusterEnvironment = ""
                clusterDescriptor = ""

                # Try to parse cluster info
                try:
                    regexResult = re.search(CLUSTER_INFO_REGEX, clusterName)
                    if regexResult.group(1) is not None:
                        clusterName = regexResult.group(1)
                    if regexResult.group(2) is not None:
                        clusterEnvironment = regexResult.group(2)
                    if regexResult.group(3) is not None:
                        clusterDescriptor = regexResult.group(3)
                except:
                    pass

                namespace = deployment["namespace"]
                deploymentId = deployment["id"]
                deploymentName = deployment["name"]

                # Get the application code from the namespace (first 3 characters)
                applicationCode = namespace[:3]

                # Get the deployment detail
                currentDeploymentIndex += 1
                print(f"{currentDeploymentIndex} of {deploymentCount} - Inspecting {clusterName}/{namespace}/{deploymentName}...")

                try:
                    responseJson = getJsonFromRhacsApi("/deployments/" + deploymentId)
                    if responseJson is not None:
                        containers = responseJson["containers"]
                        for container in containers:
                            image = container["image"]
                            imageId = image["id"]
                            imageFullName = image["name"]["fullName"]
                            
                            # Get the image detail
                            createdOn = ""
                            os = ""
                            ubiName = ""
                            ubiVersion = ""
                            ubiRelease = ""
                            try:
                                print(f"{imageFullName}")
                                responseJson = getJsonFromRhacsApi("/images/" + imageId)
                                if responseJson is not None:
                                    metadataJson = responseJson["metadata"]["v1"]
                                    createdOn = metadataJson["created"]

                                    # Try to convert createdOn from ISO format to a more readable format
                                    try:
                                        createdOn = datetime.fromisoformat(createdOn).astimezone().strftime(DATETIME_FORMAT)
                                    except:
                                        pass

                                    os = responseJson["scan"]["operatingSystem"]

                                    # Get more details if it's a rhel-based image
                                    if os.startswith(OS_ID_RHEL):
                                        for layer in metadataJson["layers"]:
                                            if layer["instruction"] == "LABEL":
                                                value = layer["value"]
                                                # UBI-specific metadata checking
                                                if UBI_IDENTIFIER_IN_LABEL in value:
                                                    regexResult = re.search(UBI_REGEX, value)
                                                    if regexResult is not None:
                                                        ubiName = regexResult.group(1)
                                                        ubiVersion = regexResult.group(2)
                                                        ubiRelease = regexResult.group(3)
                                                        # Exit the current loop
                                                        break

                                        # If the base image labels have been removed,
                                        # try to get the metadata from the url
                                        if ubiName == "":
                                            labels = metadataJson["labels"]
                                            if hasattr(labels, "url"):
                                                regexResult = re.search(UBI_REGEX, labels["url"])
                                                if regexResult is not None:
                                                    ubiName = regexResult.group(1)
                                                    ubiVersion = regexResult.group(2)
                                                    ubiRelease = regexResult.group(3)
                                            
                                            # If that failed, try to get the metadata from the labels
                                            if ubiName == "":
                                                ubiName = labels["name"]
                                                ubiVersion = labels["version"]
                                                ubiRelease = labels["release"]

                                        # Ignore non-ubi metadata
                                        if not ubiName.startswith(UBI_PREFIX):
                                            ubiName = ""
                                            ubiVersion = ""
                                            ubiRelease = ""

                            except Exception as ex:
                                os = type(ex)
                                ubiName = ex
                                print(f"Image:{imageFullName} has the following ERROR:{type(ex)=}:{ex=}.")

                            finally:
                                # Write the image detail into the CSV file
                                writer.writerow([
                                    clusterName,
                                    clusterEnvironment,
                                    clusterDescriptor,
                                    namespace,
                                    applicationCode,
                                    deploymentName,
                                    imageFullName,
                                    createdOn,
                                    os,
                                    ubiName,
                                    ubiVersion,
                                    ubiRelease
                                ])
                                f.flush()

                except Exception as ex:
                    print(f"Not completing {clusterName}/{namespace}/{deploymentName} due to ERROR:{type(ex)=}:{ex=}.")

        print(f"Successfully generated {csvFileName}\n")
                    
def getJsonFromRhacsApi(requestPath):
    url=rhacsCentralUrl + "/v1" + requestPath
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