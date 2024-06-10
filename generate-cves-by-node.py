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
CSV_HEADER = [
    "Cluster Name",
    "Environment",
    "Cluster Descriptor",
    "CVE",
    "Fixable",
    "Severity",
    "CVSS",
    "Env. Impact",
    "Impact Score",
    "Nodes",
    "Published On",
    "Discovered On",
    "Link",
    "Summary"
]
VULNERABILITY_SEVERITY = {
    "CRITICAL_VULNERABILITY_SEVERITY": "Critical",
    "IMPORTANT_VULNERABILITY_SEVERITY": "Important",
    "MODERATE_VULNERABILITY_SEVERITY": "Moderate",
    "LOW_VULNERABILITY_SEVERITY": "Low",
    "UNKNOWN_VULNERABILITY_SEVERITY": "Unknown"
}

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
    "id": "${nodeId}",
    "query": "",
    "policyQuery": "Category:Vulnerability Management",
    "scopeQuery": "CLUSTER ID: ${clusterId}",
    "pagination": {
      "offset": 0,
      "limit": 0,
      "sortOption": {
        "field": "CVSS",
        "reversed": true
      }
    }
  },
  "query": "query ${operationName}($$id: ID!, $$pagination: Pagination, $$query: String, $$policyQuery: String, $$scopeQuery: String) {\n  result: node(id: $$id) {\n    id\n    nodeVulnerabilityCount(query: $$query)\n    nodeVulnerabilities(query: $$query, pagination: $$pagination) {\n      ...nodeCVEFields\n      __typename\n    }\n    unusedVarSink(query: $$policyQuery)\n    unusedVarSink(query: $$scopeQuery)\n    __typename\n  }\n}\n\nfragment nodeCVEFields on NodeVulnerability {\n  createdAt\n  cve\n  cvss\n  envImpact\n  fixedByVersion\n  id\n  impactScore\n  isFixable(query: $$scopeQuery)\n  lastModified\n  lastScanned\n  link\n  publishedOn\n  scoreVersion\n  severity\n  summary\n  suppressActivation\n  suppressExpiry\n  suppressed\n  componentCount: nodeComponentCount\n  nodeCount\n  operatingSystem\n  __typename\n}\n"
}""")

# Prepare for API calls
rhacsCentralUrl = None
rhacsApiToken = None
outputFileName = None
authorizationHeader = None
requestContext = ssl.create_default_context()
requestContext.check_hostname = False
requestContext.verify_mode = ssl.CERT_NONE

class ClusterDetail:
    def __init__(self) -> None:
        self.clusterId = ""
        self.clusterName = ""
        self.clusterEnvironment = ""
        self.clusterDescriptor = ""
        self.cveDetails = {}
    
class CveDetail:
    def __init__(self) -> None:
        self.cve = {}
        self.nodes = []

# Main function
def main():
    # We will modify these global variables
    global rhacsCentralUrl, rhacsApiToken, outputFileName, apiHeader
    
    # Initialize arguments parser
    parser = argparse.ArgumentParser()

    parser.add_argument("-u", "--url", help="RHACS CENTRAL URL, e.g. https://central-stackrox.apps.myocpcluster.com", required=True)
    parser.add_argument("-t", "--token", help="RHACS API token", required=True)
    parser.add_argument("-o", "--output", help="Output CSV file name", required=True)
    parser.add_argument("-f", "--format", help="Output format (either csv or json)", choices=["csv", "json"], default="csv")
    arguments = parser.parse_args()
    
    rhacsCentralUrl = arguments.url
    rhacsApiToken = arguments.token
    outputFileName = arguments.output
    outputFormat = arguments.format

    # Prepare for API calls
    apiHeader = {
        "Authorization": "Bearer " + rhacsApiToken,
        "Content-Type": "application/json; charset=utf-8",
        "Content-Length": 0,
        "Accept": "application/json"
    }

    # This will contain the list of CVEs
    # Grouped by cluster, so some CVEs may appear in multiple clusters
    cvesByCluster = {}

    responseJson = getJsonFromRhacsApi("/clusters")
    if responseJson is not None:
        # Create the CSV file
        with open(outputFileName, "w", newline="") as f:
            writer = csv.writer(f, dialect="excel")
            writer.writerow(CSV_HEADER)

            # Process all clusters
            clusters = responseJson["clusters"]
            for cluster in clusters:
                clusterId = cluster["id"]
                clusterName = cluster["name"]
                clusterEnvironment = ""
                clusterDescriptor = ""

                print(f"Inspecting nodes in cluster:{clusterName}...")

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

                cvesByCluster[clusterId] = ClusterDetail()
                cvesByCluster[clusterId].clusterId = clusterId
                cvesByCluster[clusterId].clusterName = clusterName
                cvesByCluster[clusterId].clusterEnvironment = clusterEnvironment
                cvesByCluster[clusterId].clusterDescriptor = clusterDescriptor
            
                currentClusterDetail = cvesByCluster[clusterId]

                # Process all nodes in this cluster
                responseJson = getJsonFromRhacsApi("/nodes/" + clusterId)
                nodes = responseJson["nodes"]
                nodeCount = len(nodes)
                currentNodeIndex = 0
                for node in nodes:
                    nodeId = node["id"]
                    nodeName = node["name"]
 
                    currentNodeIndex += 1
                    print(f"{currentNodeIndex} of {nodeCount} - Inspecting {clusterName}/{nodeName}...")

                    try:
                        operationName = "getNodeNODE_CVE"
                        graphQlRequest = GRAPHQL_REQUEST_TEMPLATE.substitute(
                            operationName = operationName,
                            clusterId = clusterId,
                            nodeId = nodeId
                        ).replace("\n", "")

                        responseJson = getJsonFromRhacsGraphQl(operationName, graphQlRequest)
                        if responseJson is not None:
                            cves = responseJson["data"]["result"]["nodeVulnerabilities"]

                            for cve in cves:
                                # Add to the list of CVEs if it has not been added
                                cveId = cve["cve"]
                                if cveId not in currentClusterDetail.cveDetails:
                                    currentClusterDetail.cveDetails[cveId] = CveDetail()

                                currentCveDetail = currentClusterDetail.cveDetails[cveId]
                                
                                currentCveDetail.cve = cve
                                if nodeName not in currentCveDetail.nodes:
                                    currentCveDetail.nodes.append(nodeName)

                    except Exception as ex:
                        print(f"Not completing {clusterName}/{nodeName} due to ERROR:{type(ex)=}:{ex=}.")

        # Create the CSV file
        with open(outputFileName, "w", newline="", encoding="utf-8") as f:
            writer = None
            if (outputFormat == "csv"):
                writer = csv.writer(f, dialect="excel")
                writer.writerow(CSV_HEADER)

            # Sort the CVEs by environment, cluster name, and CVSS score
            sortedByClusterEnvironmentAndName = sorted(cvesByCluster,  key = lambda clusterId : (cvesByCluster[clusterId].clusterEnvironment, cvesByCluster[clusterId].clusterName))
            for clusterId in sortedByClusterEnvironmentAndName:
                clusterDetail = cvesByCluster[clusterId]

                for cveId in clusterDetail.cveDetails:
                    cveDetail = clusterDetail.cveDetails[cveId]
                    cveData = cveDetail.cve

                    # Parse the severity
                    severity = ""
                    try:
                        severity = VULNERABILITY_SEVERITY[cveData["severity"]]
                    except:
                        pass

                    if outputFormat == "csv":
                        outputRow = [
                            clusterDetail.clusterName,
                            clusterDetail.clusterEnvironment,
                            clusterDetail.clusterDescriptor,
                            cveId,
                            "Fixable" if cveData["isFixable"] else "Not Fixable",
                            severity,
                            "{0:.1f}".format(cveData["cvss"]),
                            "{0:.0f}%".format(cveData["envImpact"]*100),
                            "{0:.2f}".format(cveData["impactScore"]),
                            "\n".join(cveDetail.nodes),
                            cveData["publishedOn"] if cveData["publishedOn"] is not None else "",
                            cveData["createdAt"],
                            cveData["link"],
                            cveData["summary"]
                        ]
                        writer.writerow(outputRow)
                    elif outputFormat == "json":
                        outputRow = {
                            "clusterName": clusterDetail.clusterName,
                            "clusterEnvironment": clusterDetail.clusterEnvironment,
                            "clusterDescriptor": clusterDetail.clusterDescriptor,
                            "cve": cveId,
                            "fixable": "Fixable" if cveData["isFixable"] else "Not Fixable",
                            "severity": severity,
                            "cvss": "{0:.1f}".format(cveData["cvss"]),
                            "envImpact": "{0:.0f}%".format(cveData["envImpact"]*100),
                            "impactScore": "{0:.2f}".format(cveData["impactScore"]),
                            "nodes": "\n".join(cveDetail.nodes),
                            "publishedOn": cveData["publishedOn"] if cveData["publishedOn"] is not None else "",
                            "createdAt": cveData["createdAt"],
                            "link": cveData["link"],
                            "summary": cveData["summary"]
                        }
                        json.dump(outputRow, f, ensure_ascii=False)
                    f.flush()

        print(f"Successfully generated {outputFileName}\n")
                    
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