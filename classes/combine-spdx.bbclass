IMAGE_POSTPROCESS_COMMAND += "combine_spdx"

python combine_spdx() {
  import os
  import json

  deploy_dir_image = d.getVar("DEPLOY_DIR_IMAGE")

  # Image information.
  image_name = d.getVar("IMAGE_NAME")

  image_spdx = create_base_spdx(image_name)

  # Get SPDX for all recipes.
  for filename in os.listdir(d.getVar("SPDX_DEPLOY_DIR")):
    if filename.endswith("spdx.json"):
      with open(os.path.join(d.getVar("SPDX_DEPLOY_DIR"), filename)) as f:
        package_spdx = json.load(f)
        image_spdx["packages"].extend(package_spdx["packages"])
        image_spdx["files"].extend(package_spdx["files"])
        image_spdx["relationships"].extend(package_spdx["relationships"])


  bb.warn(image_name)
  image_manifest = d.getVar("IMAGE_MANIFEST")
  # with open(image_manifest, 'r') as f:

  image_basename = d.getVar("IMAGE_BASENAME")
  image_spdx_path = os.path.join(deploy_dir_image, f"{image_basename}.spdx.json")
  with open(image_spdx_path, 'w') as f:
    f.write(json.dumps(image_spdx, indent=4))
}