PACKAGEFUNCS_append = " write_srclist"

CVE_PRODUCT ??= "${BPN}"
CVE_VERSION ??= "${PV}"

SPDX_DEPLOY_DIR ??= "${DEPLOY_DIR}/spdx"
SPDX_TOPDIR ?= "${WORKDIR}/spdx_sstate_dir"
SPDX_OUTDIR ?= "${SPDX_TOPDIR}/${TARGET_SYS}/${PF}/"
SPDX_WORKDIR ?= "${WORKDIR}/spdx_temp/"

SPDX_EXCLUDE_NATIVE ??= "1"
SPDX_EXCLUDE_SDK ??= "1"
SPDX_EXCLUDE_PACKAGES ??= ""

do_write_spdx[dirs] = "${WORKDIR}"

# Save results in split_and_strip_files to use it during do_package.
split_and_strip_files_append() {
    if (d.getVar('INHIBIT_PACKAGE_DEBUG_SPLIT') != '1'):
        d.setVar('TEMPDBGSRCMAPPING', results)
}

# Exclude package based on variables.
# SPDX_EXCLUDE_NATIVE ??= "1"
# SPDX_EXCLUDE_SDK ??= "1"
# SPDX_EXCLUDE_PACKAGES ??= ""
def excluded_package(d, pn):
    assume_provided = (d.getVar("ASSUME_PROVIDED") or "").split()
    if pn in assume_provided:
        for p in d.getVar("PROVIDES").split():
            if p != pn:
                pn = p
                break
    if d.getVar('BPN') in ['gcc', 'libgcc']:
        #bb.debug(1, 'spdx: There is a bug in the scan of %s, skip it.' % pn)
        return True
    # The following: do_fetch, do_unpack and do_patch tasks have been deleted,
    # so avoid archiving do_spdx here.
    # -native is for the host aka during the build
    if pn.endswith('-native') and d.getVar("SPDX_EXCLUDE_NATIVE") == "1":
        return True
    # nativesdk- is for the developer SDK
    if pn.startswith('nativesdk-') and d.getVar("SPDX_EXCLUDE_SDK") == "1":
        return True
    # packagegroups have no files to scan
    if pn.startswith('packagegroup'):
        return True
    if pn.startswith('glibc-locale'):
        return True
    for p in d.getVar("SPDX_EXCLUDE_PACKAGES").split():
        if p in pn:
            return True
    return False

python write_srclist() {
    import json

    pkgdatadir = d.getVar('PKGDESTWORK')
    
    data_file = pkgdatadir + d.expand("/${PN}")

    sourceresults = d.getVar('TEMPDBGSRCMAPPING', False)
    sources = {}
    if sourceresults:
        for r in sourceresults:
            sources[r[0]] = []
            for source in r[1]:
                sourcedirents = [d.getVar('PKGD'), d.getVar('STAGING_DIR_TARGET')]
                for dirent in sourcedirents:
                    try:
                        sources[r[0]].append({source: sha256(dirent + source)})
                    except:
                        sources[r[0]].append({source: None})
        with open(data_file + ".srclist", 'w') as f:
            f.write(json.dumps(sources, sort_keys=True))
}

def sha256(fname):
    """
    Calculate SHA256 checksum for a file. 
    """

    import hashlib

    hash_sha256 = hashlib.sha256()
    with open(fname, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

python do_write_spdx() {
    """
    Write SPDX information of the package to an SPDX JSON document.
    """
    import os

    if bb.data.inherits_class('nopackages', d):
        return

    pn = d.getVar('PN')
    assume_provided = (d.getVar("ASSUME_PROVIDED") or "").split()
    if pn in assume_provided:
        for p in d.getVar("PROVIDES").split():
            if p != pn:
                pn = p
                break

    # glibc-locale: do_fetch, do_unpack and do_patch tasks have been deleted,
    # so avoid archiving source here.
    if pn.startswith('glibc-locale'):
        return
    if (d.getVar('PN') == "libtool-cross"):
        return
    if (d.getVar('PN') == "libgcc-initial"):
        return
    if (d.getVar('PN') == "shadow-sysroot"):
        return

    # We just archive gcc-source for all the gcc related recipes
    if d.getVar('BPN') in ['gcc', 'libgcc']:
        bb.debug(1, 'spdx: There is bug in scan of %s is, do nothing' % pn)
        return

    spdx_outdir = d.getVar('SPDX_OUTDIR')
    spdx_workdir = d.getVar('SPDX_WORKDIR')
    spdx_temp_dir = os.path.join(spdx_workdir, "temp")
    temp_dir = os.path.join(d.getVar('WORKDIR'), "temp")

    manifest_dir = (d.getVar('SPDX_DEPLOY_DIR') or "")
    if not os.path.exists( manifest_dir ):
        bb.utils.mkdirhier( manifest_dir )

    import json
    pkgdatadir = d.getVar('PKGDESTWORK')
    source_location = d.getVar('S')
    workdir = d.getVar('WORKDIR')
    data_file = manifest_dir + d.expand("/${PF}")

    spdx = {}

    spdx["name"] = d.getVar('PN')

    spdx["version"] = d.getVar('PV')

    package_download_location = (d.getVar('SRC_URI', True) or "")
    if package_download_location != "":
        package_download_location = package_download_location.split()[0]
    spdx["downloadLocation"] = package_download_location
    
    
    package_homepage = (d.getVar('HOMEPAGE', True) or "")
    spdx["homepage"] = package_homepage

    package_summary = (d.getVar('SUMMARY', True) or "")
    spdx["summary"] = package_summary

    cve_products = d.getVar('CVE_PRODUCT').split()
    version = d.getVar('CVE_VERSION').split("+git")[0]
    cpe_ids = []
    if cve_products:
        for product in cve_products:
            if ":" in product:
                vendor, product = product.split(":", 1)
            else:
                vendor = "*"

            cpe_id = f'cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*'
            cpe = {}
            cpe["referenceCategory"] = "SECURITY"
            cpe["referenceType"] = "http://spdx.org/rdf/references/cpe23Type"
            cpe["referenceLocator"] = cpe_id
            cpe_ids.append(cpe)
        spdx["externalRefs"] = cpe_ids

        patched_cves = get_patched_cves(d)
        patched_cves = list(patched_cves)
        patched_cves = ' '.join(patched_cves)
        
        spdx["sourceInfo"] = "CVEs fixed: " + patched_cves

    spdx_get_src(d)

    spdx['files'] = []

    ignore_dirs = ["temp"]

    for subdir, dirs, files in os.walk(spdx_workdir):
        if subdir == spdx_workdir:
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for file in files:
            filepath = os.path.join(subdir,file)
            if os.path.exists(filepath):
                spdx_file = {}
                spdx_file["checksums"] = []
                file_sha256 = {}
                file_sha256["algorithm"] = "SHA256"
                file_sha256["checksumValue"] = sha256(filepath)
                spdx_file["checksums"].append(file_sha256)
                filename = os.path.relpath(os.path.join(subdir, file), spdx_workdir)
                spdx_file["fileName"] = filename

                spdx['files'].append(spdx_file)

    tar_name = spdx_create_tarball(d, spdx_workdir, '', manifest_dir)

    
    # Save SPDX for the package in pkgdata.
    with open(data_file + ".spdx.json", 'w') as f:
        f.write(json.dumps(spdx))
}

def get_patched_cves(d):
    """
    Get patches that solve CVEs using the "CVE: " tag.
    """

    import re

    pn = d.getVar("PN")
    cve_match = re.compile("CVE:( CVE\-\d{4}\-\d+)+")

    # Matches last CVE-1234-211432 in the file name, also if written
    # with small letters. Not supporting multiple CVE id's in a single
    # file name.
    cve_file_name_match = re.compile(".*([Cc][Vv][Ee]\-\d{4}\-\d+)")

    patched_cves = set()
    bb.debug(2, "Looking for patches that solves CVEs for %s" % pn)
    for url in src_patches(d):
        patch_file = bb.fetch.decodeurl(url)[2]

        if not os.path.isfile(patch_file):
            bb.error("File Not found: %s" % patch_file)
            raise FileNotFoundError

        # Check patch file name for CVE ID
        fname_match = cve_file_name_match.search(patch_file)
        if fname_match:
            cve = fname_match.group(1).upper()
            patched_cves.add(cve)
            bb.debug(2, "Found CVE %s from patch file name %s" % (cve, patch_file))

        with open(patch_file, "r", encoding="utf-8") as f:
            try:
                patch_text = f.read()
            except UnicodeDecodeError:
                bb.debug(1, "Failed to read patch %s using UTF-8 encoding"
                        " trying with iso8859-1" %  patch_file)
                f.close()
                with open(patch_file, "r", encoding="iso8859-1") as f:
                    patch_text = f.read()

        # Search for one or more "CVE: " lines
        text_match = False
        for match in cve_match.finditer(patch_text):
            # Get only the CVEs without the "CVE: " tag
            cves = patch_text[match.start()+5:match.end()]
            for cve in cves.split():
                bb.debug(2, "Patch %s solves %s" % (patch_file, cve))
                patched_cves.add(cve)
                text_match = True

        if not fname_match and not text_match:
            bb.debug(2, "Patch %s doesn't solve CVEs" % patch_file)

    return patched_cves

# Run do_unpack and do_patch
def spdx_get_src(d):
    import shutil
    spdx_workdir = d.getVar('SPDX_WORKDIR')
    spdx_sysroot_native = d.getVar('STAGING_DIR_NATIVE')
    pn = d.getVar('PN')
    
    # The kernel class functions require it to be on work-shared, so we dont change WORKDIR
    if not is_work_shared(d):
        # Change the WORKDIR to make do_unpack do_patch run in another dir.
        d.setVar('WORKDIR', spdx_workdir)
        # Restore the original path to recipe's native sysroot (it's relative to WORKDIR).
        d.setVar('STAGING_DIR_NATIVE', spdx_sysroot_native)

        # The changed 'WORKDIR' also caused 'B' changed, create dir 'B' for the
        # possibly requiring of the following tasks (such as some recipes's
        # do_patch required 'B' existed).
        bb.utils.mkdirhier(d.getVar('B'))

        bb.build.exec_func('do_unpack', d)
    # Copy source of kernel to spdx_workdir
    if is_work_shared(d):
        d.setVar('WORKDIR', spdx_workdir)
        d.setVar('STAGING_DIR_NATIVE', spdx_sysroot_native)
        src_dir = spdx_workdir + "/" + d.getVar('PN')+ "-" + d.getVar('PV') + "-" + d.getVar('PR')
        bb.utils.mkdirhier(src_dir)
        if bb.data.inherits_class('kernel',d):
            share_src = d.getVar('STAGING_KERNEL_DIR')
        cmd_copy_share = "cp -rf " + share_src + "/* " + src_dir + "/"
        cmd_copy_kernel_result = os.popen(cmd_copy_share).read()
        bb.note("cmd_copy_kernel_result = " + cmd_copy_kernel_result)
        
        git_path = src_dir + "/.git"
        if os.path.exists(git_path):
            remove_dir_tree(git_path)

    # Make sure gcc and kernel sources are patched only once
    if not (d.getVar('SRC_URI') == "" or is_work_shared(d)):
        bb.build.exec_func('do_patch', d)

    # Some userland has no source.
    if not os.path.exists( spdx_workdir ):
        bb.utils.mkdirhier(spdx_workdir)

def is_work_shared(d):
    pn = d.getVar('PN')
    return bb.data.inherits_class('kernel', d) or pn.startswith('gcc-source')

def remove_dir_tree(dir_name):
    import shutil
    try:
        shutil.rmtree(dir_name)
    except:
        pass


def spdx_create_tarball(d, srcdir, suffix, ar_outdir):
    """
    create the tarball from srcdir
    """
    import tarfile, shutil

    # Make sure we are only creating a single tarball for gcc sources
    #if (d.getVar('SRC_URI') == ""):
    #    return
    # For the kernel archive, srcdir may just be a link to the
    # work-shared location. Use os.path.realpath to make sure
    # that we archive the actual directory and not just the link.
    srcdir = os.path.realpath(srcdir)
    bb.utils.mkdirhier(ar_outdir)

    filename = get_tar_name(d, suffix)
    tarname = os.path.join(ar_outdir, filename)
    bb.warn('Creating %s' % tarname)
    tar = tarfile.open(tarname, 'w:bz2')
    tar.add(srcdir, arcname=os.path.basename(srcdir), filter=exclude_useless_paths)
    tar.close()
    return tarname

def get_tar_name(d, suffix):
    """
    get the name of tarball
    """

    # Make sure we are only creating a single tarball for gcc sources
    #if (d.getVar('SRC_URI') == ""):
    #    return
    # For the kernel archive, srcdir may just be a link to the
    # work-shared location. Use os.path.realpath to make sure
    # that we archive the actual directory and not just the link.
    if suffix:
        filename = '%s-%s.tar.bz2' % (d.getVar('PF'), suffix)
    else:
        filename = '%s.tar.bz2' % d.getVar('PF')

    return filename

def exclude_useless_paths(tarinfo):
    if tarinfo.isdir():
        if tarinfo.name.endswith('/temp'):
            return None
    return tarinfo

addtask do_write_spdx after do_patch before do_build