QT = core network

include($$PWD/qtsslutils.pri)

#VERSION = 1.0

TEMPLATE = lib
TARGET = $$qtLibraryTarget(QtSslUtils$$QT_LIBINFIX)
CONFIG += module create_prl
DEFINES+= QT_BUILD_SSLUTILS_LIB
mac:QMAKE_FRAMEWORK_BUNDLE_NAME = $$TARGET
#INCLUDEPATH+= $$PWD/common

headersDataFiles.files+= $$PWD/qsslutils.h

# install to Qt installation directory if no PREFIX specified
_PREFIX = $$PREFIX
isEmpty(_PREFIX) {
	INSTALL_HEADER_PATH = $$[QT_INSTALL_HEADERS]/QtSslUtils/
	INSTALL_LIB_PATH = $$[QT_INSTALL_LIBS]
} else {

	INSTALL_HEADER_PATH = $$PREFIX/include/QtSslUtils/
	INSTALL_LIB_PATH = $$PREFIX/lib
}
message(install to: $$INSTALL_LIB_PATH)
headersDataFiles.path = $$INSTALL_HEADER_PATH
target.path = $$INSTALL_LIB_PATH

INSTALLS+= target headersDataFiles
