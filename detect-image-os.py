import csv
import json
import argparse
import re
import ijson

# Constants
CSV_HEADER = ["Counter", "Image Name", "OS", "UBI Name", "UBI Version", "UBI Release", "Metadata"]
UBI_IDENTIFIER_IN_LABEL = "\"url\"=\"https://access.redhat.com/containers/#/registry.access.redhat.com/ubi"
OS_ID_RHEL = "rhel"
UBI_REGEX = r"(https\://.+/([^/]+)/images/(\d[\d.]*)\-(\d[\d.]*))"

def main():
    # Initialize arguments parser
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", help="Input JSON file name", required=True)
    parser.add_argument("-o", "--output", help="Output CSV file name", required=True)
    arguments = parser.parse_args()

    with open(arguments.input, "rb") as inputFile, open(arguments.output, "w", newline="") as outputFile:
        # Create the CSV file
        writer = csv.writer(outputFile, dialect="excel")
        writer.writerow(CSV_HEADER)

        counter=0
        for record in ijson.items(inputFile, "item"):
            fullName = record["name"]["fullName"]

            # Print the progress
            counter += 1
            print(f"{counter}. Processing {fullName}...")

            os = record["scan"]["operatingSystem"]
            ubiName = ""
            ubiVersion = ""
            ubiRelease = ""

            # Get more details if it's a rhel-based image
            if os.startswith(OS_ID_RHEL):
                labels = record["metadata"]["v1"]["labels"]
                for layer in record["metadata"]["v1"]["layers"]:
                    if layer["instruction"] == "LABEL":
                        value = layer["value"]
                        # UBI-specific metadata checking
                        if UBI_IDENTIFIER_IN_LABEL in value:
                            regexResult = re.search(UBI_REGEX, value)
                            ubiName = regexResult.group(2)
                            ubiVersion = regexResult.group(3)
                            ubiRelease = regexResult.group(4)
                            # Exit the current loop
                            break

                # If the base image labels have been removed,
                # try to get the metadata from the url
                if ubiName == "":
                    url = labels["url"]
                    regexResult = re.search(UBI_REGEX, url)
                    if regexResult is not None:
                        ubiName = regexResult.group(2)
                        ubiVersion = regexResult.group(3)
                        ubiRelease = regexResult.group(4)
                    else:
                        # If that failed, try to get the metadata from the labels
                        ubiName = labels["name"]
                        ubiVersion = labels["version"]
                        ubiRelease = labels["release"]

            writer.writerow([
                counter,
                fullName,
                os,
                ubiName,
                ubiVersion,
                ubiRelease,
                json.dumps(labels, indent=2)
            ])

    print(f"Successfully generated {arguments.output}\n")


if __name__=="__main__": 
    main() 