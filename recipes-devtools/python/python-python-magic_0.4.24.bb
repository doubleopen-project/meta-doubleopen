
SUMMARY = "File type identification using libmagic"
HOMEPAGE = "http://github.com/ahupp/python-magic"
AUTHOR = "Adam Hupp <adam@hupp.org>"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://LICENSE;md5=61495c152d794e6be5799a9edca149e3"

SRC_URI = "https://files.pythonhosted.org/packages/3a/70/76b185393fecf78f81c12f9dc7b1df814df785f6acb545fc92b016e75a7e/python-magic-0.4.24.tar.gz"
SRC_URI[md5sum] = "7a1629d43ef506f29f2b0256510d25aa"
SRC_URI[sha256sum] = "de800df9fb50f8ec5974761054a708af6e4246b03b4bdaee993f948947b0ebcf"

S = "${WORKDIR}/python-magic-0.4.24"

RDEPENDS_${PN} = ""

inherit setuptools
