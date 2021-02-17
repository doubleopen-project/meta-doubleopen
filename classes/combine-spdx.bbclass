inherit doubleopen-common

IMAGE_POSTPROCESS_COMMAND += "combine_spdx"

python combine_spdx() {
    """
    Creates an SPDX JSON document for the taget image by combining the SPDX documents
    of the included packages.
    """
    import os
    import json

    deploy_dir_image = d.getVar("DEPLOY_DIR_IMAGE")

    # Initialize the SPDX for image.
    image_name = d.getVar("IMAGE_NAME")
    image_spdx = create_base_spdx(image_name)

    # Get SPDX for all recipes and add packages, files and relationships to the image's
    # SPDX.
    for filename in os.listdir(d.getVar("SPDX_DEPLOY_DIR")):
        if filename.endswith("spdx.json"):
            with open(os.path.join(d.getVar("SPDX_DEPLOY_DIR"), filename)) as f:
                package_spdx = json.load(f)
                image_spdx["packages"].extend(package_spdx["packages"])
                image_spdx["files"].extend(package_spdx["files"])
                image_spdx["relationships"].extend(package_spdx["relationships"])
    
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
            sub_package_name = sub_package.split()[0]
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

    image_basename = d.getVar("IMAGE_BASENAME")
    image_spdx_path = os.path.join(deploy_dir_image, f"{image_basename}.spdx.json")
    with open(image_spdx_path, 'w') as f:
        f.write(json.dumps(image_spdx, indent=4))
}