
QSslUtils is a collection high level functions for creating RSA keys, CA certificates, certificate signing requests and signing CSRs.

### Building

QSslUtils can be built directly into your project if your project is [LGPL3](http://www.gnu.org/licenses/lgpl-3.0.en.html) compatible.  If your project is closed source, you can build QSslUtils as a dynamic library and link against it.

#### Building into your project

1. Clone as a git submodule or download QSslUtils.  If you download, unzip as a directory to be under your project's directory. 
2. Include the qtsslutils.pri file in your projects .pro file

    include(QtSslUtils/qtsslutils.pri)

    INCLUDEPATH=+ QSslUtils

3. Add QZEROCONF_STATIC define in your projects .pro file

    DEFINES= QSSLUTILS_STATIC

#### Compiling as a dynamic library

1. Clone or download QSslUtils.  If you download, unzip.
2. Enter the QtSslUtils directory, run qmake, then make, then (sudo) make install

### API

#### Creating a CA

1) Include header

```c++
#include "qsslutils.h"
```
2) Create an super secret key and then pass that key to the createCA function.  The last two parameters to createCA are serial number and days the cert should be valid for.

```c++
QSslEvpKey superSecretKey = QSslUtils::generateRSAKey(2048);
QSslX509 ca = QSslUtils::createCA(superSecretKey, "US", "MD", "Fort Meade", "FooBar NSA", "IT", 1, 30);
```
QSslEvpKey and QSslX509 are smart pointers with custom deleters so they will call the correct ssl free function when their reference count goes to 0.

#### Create a local certificate

1) Include header

```c++
#include "qsslutils.h"
```
2) Create a RSA key to be used for the intermediate or local certificate.

3) Create a Certificate Signing Request.

4) Then use the created CA from above "Creating a CA" and it's super secret key to sign the CSR.  The last two parameters to signCSR are serial number and days the cert should be valid for.

```c++
QSslEvpKey reqKey = QSslUtils::generateRSAKey(2048);
QSslX509Req req = QSslUtils::createCSR(reqKey, "CA", "Ontario", "Ottawa", "FooBar CSIS", "IT");
QSslX509 cert = QSslUtils::signCSR(ca, superSecretKey, req, 1, 30);
```
QSslEvpKey, QSslX509Req and QSslX509 are smart pointers with custom deleters so they will call the correct ssl free function when their reference count goes to 0.

