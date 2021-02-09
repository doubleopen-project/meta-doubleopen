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