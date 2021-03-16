inherit doubleopen-common
inherit oe-pkgdata-util

IMAGE_POSTPROCESS_COMMAND += "combine_spdx"

python combine_spdx() {
    """
    Creates an SPDX JSON document for the taget image by combining the SPDX documents
    of the included packages. Also processes the srclist files for all recipes and 
    adds the relationships between binary and source files to the SPDX.
    """
    import os
    import json

    deploy_dir_image = d.getVar("DEPLOY_DIR_IMAGE")

    # Initialize the SPDX for image.
    image_name = d.getVar("IMAGE_NAME")
    image_spdx = create_base_spdx(image_name)

    # Store relationships between binary files and their sources in dictionary.
    # Key: SPDXID of the binary file, value: list of sha256 checksums of sources.
    binary_source_relationships = {}

    # Get SPDX for all recipes and add packages, files and relationships to the image's
    # SPDX.
    for filename in os.listdir(d.getVar("SPDX_DEPLOY_DIR")):
        if filename.endswith("spdx.json"):
            with open(os.path.join(d.getVar("SPDX_DEPLOY_DIR"), filename)) as f:
                package_spdx = json.load(f)
                image_spdx["packages"].extend(package_spdx["packages"])
                image_spdx["files"].extend(package_spdx["files"])
                image_spdx["relationships"].extend(package_spdx["relationships"])
            
                srclist_name = filename[:-9] + "srclist.json"

                # Check if package has a corresponding srclist file, store relationships
                # in the dictionary if the file exists.
                if os.path.exists(os.path.join(d.getVar("SPDX_DEPLOY_DIR"), srclist_name)):
                    with open(os.path.join(d.getVar("SPDX_DEPLOY_DIR"), srclist_name)) as f:
                        for binary_file in json.load(f):
                            for spdx_file in package_spdx["files"]:
                                for checksum in spdx_file["checksums"]:
                                    if checksum["algorithm"] == "SHA256":
                                        if binary_file["sha256"] == checksum["checksumValue"]:
                                            binary_file_spdx_id = spdx_file["SPDXID"]
                                            binary_source_relationships[binary_file_spdx_id] = [source["sha256"] for source in binary_file["sources"] if source["sha256"]]
                                            break


    # Store SPDXID's of files from the SPDX in a dict with sha256 as the key to
    # make lookups faster.
    sha256_to_spdxid = {}
    for spdx_file in image_spdx["files"]:
        for checksum in spdx_file["checksums"]:
            if checksum["algorithm"] == "SHA256":
                sha256 = checksum["checksumValue"]
        sha256_to_spdxid[sha256] = spdx_file["SPDXID"]

    # Add relationships between binaries and their source.
    for binary, sources in binary_source_relationships.items():
        for source in sources:
            if source in sha256_to_spdxid:
                relationship = {}
                relationship["spdxElementId"] = binary
                relationship["relatedSpdxElement"] = sha256_to_spdxid[source]
                relationship["relationshipType"] = "GENERATED_FROM"
                image_spdx["relationships"].append(relationship)
            else:
                bb.warn(f"No spdxid found for {source} of {binary}")



    # Create SPDX package for the image.
    image_package = create_spdx_package(
        name=d.getVar("IMAGE_NAME"), version=d.getVar("PV"), id_prefix="Image",
        )

    # Image manifest contains a list of packages from recipes that are included in the
    # final image. Find the correct SPDX package for these and add a relationship
    # between the image and them.
    image_manifest = d.getVar("IMAGE_MANIFEST")
    with open(image_manifest, 'r') as f:
        for sub_package in f:
            sub_package_name = lookup_pkg(sub_package.split()[0], d.getVar("PKGDATA_DIR"), True)
            for spdx_package in image_spdx["packages"]:
                if spdx_package["name"] == sub_package_name and "-Package-" in spdx_package["SPDXID"]:
                    # TODO: Does not find package for all packages in manifest, meaning
                    # that all packages in manifest are not included in recipes' PACKAGES
                    # variable. Why?
                    bb.warn(f"Found package for {sub_package_name}")
                    relationship = {}
                    relationship["spdxElementId"] = spdx_package["SPDXID"]
                    relationship["relatedSpdxElement"] = image_package["SPDXID"]
                    relationship["relationshipType"] = "PACKAGE_OF"
                    image_spdx["relationships"].append(relationship)
                    break
            else:
                bb.warn(f"Did not find package for {sub_package_name}")

    image_spdx["packages"].append(image_package)
    image_spdx["documentDescribes"] = [image_package["SPDXID"]]
    image_spdx["hasExtractedLicensingInfos"] = []
    image_spdx["snippets"] = []
    image_spdx["annotations"] = []

    image_basename = d.getVar("IMAGE_BASENAME")
    image_spdx_path = os.path.join(deploy_dir_image, f"{image_basename}.spdx.json")
    with open(image_spdx_path, 'w') as f:
        f.write(json.dumps(image_spdx, indent=4))
}