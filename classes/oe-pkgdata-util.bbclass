# Modified from scrips/oe-pkgdata-util.
#
# Originally header:
#
# OpenEmbedded pkgdata utility
#
# Written by: Paul Eggleton <paul.eggleton@linux.intel.com>
#
# Copyright 2012-2015 Intel Corporation
#
# SPDX-License-Identifier: GPL-2.0-only
#
# Modifications:
#
# Copyright 2021 HH Partners
#
# SPDX-License-Identifier: GPL-2.0-only

def lookup_pkg(package, pkgdata_dir, reverse):
    # Handle both multiple arguments and multiple values within an arg (old syntax)
    pkgs = []
    pkgs.append(package)

    mappings = lookup_pkglist(pkgs, pkgdata_dir, reverse)

    if len(mappings) < len(pkgs):
        missing = list(set(pkgs) - set(mappings.keys()))
        bb.error("The following packages could not be found: %s" % ', '.join(missing))
        sys.exit(1)

    if reverse:
        items = list(mappings.values())
    else:
        items = []
        for pkg in pkgs:
            items.extend(mappings.get(pkg, []))

    return items[0]

def lookup_pkglist(pkgs, pkgdata_dir, reverse):
    from collections import defaultdict, OrderedDict
    import os
    if reverse:
        mappings = OrderedDict()
        for pkg in pkgs:
            revlink = os.path.join(pkgdata_dir, "runtime-reverse", pkg)
            bb.debug(1, revlink)
            if os.path.exists(revlink):
                mappings[pkg] = os.path.basename(os.readlink(revlink))
    else:
        mappings = defaultdict(list)
        for pkg in pkgs:
            pkgfile = os.path.join(pkgdata_dir, 'runtime', pkg)
            if os.path.exists(pkgfile):
                with open(pkgfile, 'r') as f:
                    for line in f:
                        fields = line.rstrip().split(': ')
                        if fields[0] == 'PKG_%s' % pkg:
                            mappings[pkg].append(fields[1])
                            break
    return mappings