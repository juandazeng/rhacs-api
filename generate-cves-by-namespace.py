import csv
import argparse
import json
import ssl
import re
from string import Template
from urllib.request import urlopen, Request
from urllib.parse import urlencode
from datetime import datetime

# Constants
CSV_HEADER = ["Cluster Name", "Environment", "Cluster Descriptor", "Namespace", "Total CVEs", "Fixable CVEs"]
IS_INCLUDE_OPENSHIFT_NAMESPACE = False

# The cluster regex matches the following:
# ocps4 - uat_abc_def123 <-- cluster name: ocps4, environment: uat, cluster descriptor: abc_def123
# ocps4 - uat            <-- cluster name: ocps4, environment: uat
# ocps4                  <-- cluster name: ocps4
CLUSTER_INFO_REGEX = r"([^\W_]+)(?:[\W_]+([^\W_]+)(?:[\W_]+(.*))?)?$"

# GraphQL request payload
GRAPHQL_REQUEST_TEMPLATE = Template("""
{
  "operationName": "${operationName}",
  "variables": {
    "query": "cluster:${clusterName}",
    "policyQuery": "Category:Vulnerability Management",
    "pagination": {
      "offset": 0,
      "limit": 0,
      "sortOption": {
        "field": "Namespace Risk Priority",
        "reversed": false
      }
    }
  },
  "query": "query ${operationName}($$query: String, $$policyQuery: String, $$pagination: Pagination) {\n  results: namespaces(query: $$query, pagination: $$pagination) {\n    ...namespaceFields\n    unusedVarSink(query: $$policyQuery)\n    __typename\n  }\n  count: namespaceCount(query: $$query)\n}\n\nfragment namespaceFields on Namespace {\n  metadata {\n    id\n    clusterName\n    clusterId\n    priority\n    name\n    __typename\n  }\n  imageVulnerabilityCounter {\n    all {\n      fixable\n      total\n      __typename\n    }\n    critical {\n      fixable\n      total\n      __typename\n    }\n    important {\n      fixable\n      total\n      __typename\n    }\n    moderate {\n      fixable\n      total\n      __typename\n    }\n    low {\n      fixable\n      total\n      __typename\n    }\n    __typename\n  }\n  deploymentCount\n  imageCount(query: $$query)\n  policyStatusOnly(query: $$policyQuery)\n  latestViolation(query: $$policyQuery)\n  __typename\n}\n"
}""")

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
    global rhacsCentralUrl, rhacsApiToken, csvFileName, apiHeader
    
    # Initialize arguments parser
    parser = argparse.ArgumentParser()

    parser.add_argument("-u", "--url", help="RHACS CENTRAL URL, e.g. https://central-stackrox.apps.myocpcluster.com", required=True)
    parser.add_argument("-t", "--token", help="RHACS API token", required=True)
    parser.add_argument("-o", "--output", help="Output CSV file name", required=True)
    arguments = parser.parse_args()
    
    rhacsCentralUrl = arguments.url
    rhacsApiToken = arguments.token
    csvFileName = arguments.output

    # Prepare for API calls
    apiHeader = {
        "Authorization": "Bearer " + rhacsApiToken,
        "Content-Type": "application/json; charset=utf-8",
        "Content-Length": 0,
        "Accept": "application/json"
    }

    responseJson = getJsonFromRhacsApi("/clusters")
    if responseJson is not None:
        # Create the CSV file
        with open(csvFileName, "w", newline="") as f:
            writer = csv.writer(f, dialect="excel")
            writer.writerow(CSV_HEADER)

            # Process all clusters
            clusters = responseJson["clusters"]
            for cluster in clusters:
                clusterId = cluster["id"]
                clusterName = cluster["name"]
                clusterEnvironment = ""
                clusterDescriptor = ""

                print(f"Inspecting {clusterName}...")

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

                try:
                    operationName = "getNamespaces"
                    graphQlRequest = GRAPHQL_REQUEST_TEMPLATE.substitute(
                        operationName = operationName,
                        clusterName = clusterName
                    ).replace("\n", "")

                    responseJson = getJsonFromRhacsGraphQl(operationName, graphQlRequest)
                    if responseJson is not None:
                        namespaces = responseJson["data"]["results"]

                        # Skip all openshift namespaces unless IS_INCLUDE_OPENSHIFT_NAMESPACE is True
                        namespacesToBeInspected = namespaces if IS_INCLUDE_OPENSHIFT_NAMESPACE else [namespace for namespace in namespaces if not namespace["metadata"]["name"].startswith("openshift")] 

                        namespaceCount = len(namespacesToBeInspected)
                        currentNamespaceIndex = 0
                        for namespace in namespacesToBeInspected:
                            namespaceName = namespace["metadata"]["name"]
                            cveInfo = namespace["imageVulnerabilityCounter"]["all"]
                            cveCount = cveInfo["total"]
                            fixableCveCount = cveInfo["fixable"]

                            currentNamespaceIndex += 1
                            print(f"{currentNamespaceIndex} of {namespaceCount} - Inspecting {clusterName}/{namespaceName}...")

                            # Write the cve counts into the CSV file
                            writer.writerow([
                                clusterName,
                                clusterEnvironment,
                                clusterDescriptor,
                                namespaceName,
                                cveCount,
                                fixableCveCount
                            ])
                            f.flush()

                except Exception as ex:
                    print(f"Not completing {clusterName} due to ERROR:{type(ex)=}:{ex=}.")

        print(f"Successfully generated {csvFileName}\n")
                    
def getJsonFromRhacsApi(requestPath):
    url=rhacsCentralUrl + "/v1" + requestPath
    with urlopen(Request(
        url=url,
        headers=apiHeader),
        context=requestContext) as response:
        if response.status != 200:
            print(f"Error: {response.status} - {response.msg} for request:{url}")
            return None
        else:
            return json.loads(response.read())
        
def getJsonFromRhacsGraphQl(operationName, graphQlRequest):
    url = rhacsCentralUrl + "/api/graphql"
    params = {"opname": operationName}
    url_with_params = f"{url}?{urlencode(params)}"
    jsonBody = graphQlRequest.encode('utf-8')
    apiHeader["Content-Length"] = len(jsonBody)

    with urlopen(Request(
        url=url_with_params,
        method="POST",
        headers=apiHeader),
        data=jsonBody,
        context=requestContext) as response:
        if response.status != 200:
            print(f"Error: {response.status} - {response.msg} for request:{url}")
            return None
        else:
            return json.loads(response.read())

if __name__=="__main__": 
    main() 