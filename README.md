# Double Open's meta layer for Yocto

## Description

This meta layer is intended for use with Double Open's open source license compliance workflow. The
layer saves information from a Yocto build that is required for the workflow.

### SPDX

The layer saves SPDX documents describing the packages of the build in json format to `deploy/spdx`.

![SPDX Format](./spdx.mmd.svg)

### Source archive

The layer saves source archives of the packages to `deploy/spdx`.

### Srclist

`create-srclist.bbclass` adds a function to `do_package` to save mapping between binary files
produced by the recipe and source files 

### CVE data

`cve-data.bbclass` includes helper utilities to extract CVE related information for the recipes.

## Instructions

Add the layer to `bblayers.conf`. Add `INHERIT += "doubleopen"` to `local.conf`.
