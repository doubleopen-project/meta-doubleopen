def excluded_package(d, pn):
    """
    Exclude package based on variables.

    SPDX_EXCLUDE_NATIVE ??= "1"
    SPDX_EXCLUDE_SDK ??= "1"
    SPDX_EXCLUDE_PACKAGES ??= ""
    """
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

def sha1(fname):
    """
    Calculate SHA1 checksum for a file. 
    """

    import hashlib

    hash_sha1 = hashlib.sha1()
    with open(fname, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha1.update(chunk)
    return hash_sha1.hexdigest()

def is_work_shared(d):
    pn = d.getVar('PN')
    return bb.data.inherits_class('kernel', d) or pn.startswith('gcc-source')

def remove_dir_tree(dir_name):
    """
    Remove directory tree.
    """
    import shutil
    try:
        shutil.rmtree(dir_name)
    except:
        pass

def spdx_create_tarball(d, srcdir, ar_outdir):
    """
    create the tarball from srcdir
    """
    import tarfile, shutil

    # For the kernel archive, srcdir may just be a link to the
    # work-shared location. Use os.path.realpath to make sure
    # that we archive the actual directory and not just the link.
    srcdir = os.path.realpath(srcdir)
    bb.utils.mkdirhier(ar_outdir)
    filename = '%s.tar.bz2' % d.getVar('PF')
    tarname = os.path.join(ar_outdir, filename)
    tar = tarfile.open(tarname, 'w:bz2')
    tar.add(srcdir, arcname=os.path.basename(srcdir), filter=exclude_useless_paths_and_strip_metadata)
    tar.close()
    return tarname

def exclude_useless_paths_and_strip_metadata(tarinfo):
    if tarinfo.isdir():
        # Yocto saves logs in /temp, so delete it before archiving.
        if tarinfo.name.endswith('/temp'):
            return None
        if tarinfo.name.endswith('/.git'):
            return None

    import subprocess

    if not tarinfo.isdir() and os.path.isfile(tarinfo.name):
        bb.debug(3, "Running file on {tarinfo}.".format(tarinfo=tarinfo.name))
        mime = subprocess.Popen(["file", "-b", tarinfo.name], stdout=subprocess.PIPE).stdout.read().decode('utf-8').strip()
        if not "text" in mime and mime != "empty":
            bb.debug(3, "Filtering file {tarinfo} from the archive as its filetype is {mime}.".format(tarinfo=tarinfo.name, mime=mime))
            return None

    # Clear metadata of the file to make checksum of the tar deterministic.
    tarinfo.mtime = 0
    tarinfo.uid = 0
    tarinfo.uname = ''
    tarinfo.gid = 0
    tarinfo.gname = ''

    return tarinfo

def create_base_spdx(name):
    import uuid
    from datetime import datetime, timezone

    spdx = {}
    # Document Creation information
    spdx["spdxVersion"] = "SPDX-2.2"
    spdx["dataLicense"] = "CC0-1.0"
    spdx["SPDXID"] = "SPDXRef-{name}".format(name=name)
    spdx["name"] = name
    spdx["documentNamespace"] = "http://spdx.org/spdxdocs/" + spdx["name"] + str(uuid.uuid4())
    spdx["creationInfo"] = {}
    creation_time = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    spdx["creationInfo"]["created"] = creation_time
    spdx["creationInfo"]["licenseListVersion"] = "3.11"
    spdx["creationInfo"]["comment"] = "This document was created by analyzing the source of the Yocto recipe during the build."
    spdx["creationInfo"]["creators"] = ["Tool: meta-doubleopen", "Organization: Double Open Project ()", "Person: N/A ()"]
    spdx["packages"] = []
    spdx["files"] = []
    spdx["relationships"] = []
    return spdx

def create_spdx_package(name, version, id_prefix, source_location=None, homepage=None, license_declared=None, summary=None, description=None, external_refs=None, source_info=None):
    # Package Information
    package = {}
    package["name"] = name
    package["SPDXID"] = "SPDXRef-" + id_prefix + "-" + name
    package["versionInfo"] = version
    if source_location:
        package["downloadLocation"] = source_location
    else:
        package["downloadLocation"] = "NOASSERTION"
    if homepage:
        package["homepage"] = homepage
    package["licenseConcluded"] = "NOASSERTION"
    package["licenseInfoFromFiles"] = ["NOASSERTION"]
    if license_declared:
        package["licenseDeclared"] = license_declared
    else:
        package["licenseDeclared"] = "NOASSERTION"
    if summary:
        package["summary"] = summary
    if description:
        package["description"] = description
    if external_refs:
        package["externalRefs"] = external_refs
    if source_info:
        package["sourceInfo"] = source_info
    package["copyrightText"] = "NOASSERTION"
    return package
