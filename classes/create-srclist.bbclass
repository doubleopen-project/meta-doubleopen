# Save debug information to srclist files
#
# This saves debug information provided by dwarfsrcfiles during do_package to files in pkgdata folder.
# The debug information maps binaries produced by the recipe to the source files used to build those
# binaries. Hash values of the files (binary and source) are calculated to enable identification
# later.

inherit doubleopen-common

PACKAGEFUNCS_append = " write_srclist"

# During do_package, debug info is saved in `results` variable. We need this info later to
# determine relationships between source files and binaries, so save the data to be used later.
split_and_strip_files_append() {
    if (d.getVar('INHIBIT_PACKAGE_DEBUG_SPLIT') != '1'):
        d.setVar('TEMPDBGSRCMAPPING', results)
}

python write_srclist() {
    """
    This function is added to do_package to write srclist.json based on the debug information saved
    to the pkgdata directory.
    """
    import json

    pkgdatadir = d.getVar('PKGDESTWORK')
    data_file = pkgdatadir + d.expand("/${PF}")
    sourceresults = d.getVar('TEMPDBGSRCMAPPING', False)
    sources = []

    if sourceresults:
        for binary_path in sourceresults:
            # In addition to lists with binary_path[0] being the path of the binary and 
            # binary_path[1] the list of source files used, sourceresults includes just plain
            # strings of filepaths. Skip these.
            if isinstance(binary_path, str):
                continue

            binary = {}
            binary["path"] = binary_path[0]
            binary["sha256"] = sha256(binary["path"])
            binary["sources"] = []

            for source in binary_path[1]:
                # The debug information includes pahts to source for the binary in the build
                # environment. Some of the source files can be found by appending the path to source
                # to PKGD and some to STAGING_DIR_TARGET, so check them both. This does not find
                # the source files for 
                sourcedirents = [d.getVar('PKGD'), d.getVar('STAGING_DIR_TARGET')]
                success = False
                source_file = {}
                source_file["path"] = source
                for dirent in sourcedirents:
                    try:
                        source_file["sha256"] = sha256(dirent + source)
                        success = True
                    except:
                        continue
                if success == False:
                    source_file["sha256"] = None

                binary["sources"].append(source_file)

            sources.append(binary)

        with open(data_file + ".srclist.json", 'w') as f:
            f.write(json.dumps(sources, sort_keys=True))

        # Outputting sourceresults for development purposes.
        # TODO: Delete.
        with open(data_file + ".sourceresults.json", 'w') as f:
            f.write(json.dumps(sourceresults, sort_keys=True))
}