/**************************************************************************************************
---------------------------------------------------------------------------------------------------
        Copyright (C) 2022  Jonathan Bagg
        This file is part of QtSslUtils.

        QtSslUtils is free software: you can redistribute it and/or modify
        it under the terms of the GNU Lesser General Public License as published by
        the Free Software Foundation, either version 3 of the License, or
        (at your option) any later version.

        QtSslUtils is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU Lesser General Public License for more details.

        You should have received a copy of the GNU Lesser General Public License
        along with QtSslUtils.  If not, see <http://www.gnu.org/licenses/>.
---------------------------------------------------------------------------------------------------
   Project name : QtSslUtils
   File name    : qsslutils.h
   Created      : 26 Feb 2022
   Author(s)    : Jonathan Bagg
---------------------------------------------------------------------------------------------------
   QSslUtils class definition
---------------------------------------------------------------------------------------------------
**************************************************************************************************/
#ifndef QSSLUTILS_H
#define QSSLUTILS_H

#if (!defined(QT_STATIC) && !defined(QSSLUTILS_STATIC))
#	ifdef QT_BUILD_SSLUTILS_LIB
#		define Q_SSLUTILS_EXPORT Q_DECL_EXPORT
#	else
#	define Q_SSLUTILS_EXPORT Q_DECL_IMPORT
#	endif
#else
#	define Q_SSLUTILS_EXPORT
#endif

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <QSharedPointer>

using QSslEvpKey = QSharedPointer<EVP_PKEY>;
using QSslX509 = QSharedPointer<X509>;
using QSslX509Req = QSharedPointer<X509_REQ>;

class Q_SSLUTILS_EXPORT QSslUtils
{
public:
	static QSslEvpKey generateRSAKey(uint32_t bits);
	static QSslX509Req createCSR(const QSslEvpKey &publicKey, const char *country, const char *province, const char *city, const char *org, const char *common);
	static QSslX509 signCSR(const QSslX509 &ca, const QSslEvpKey &caKey, const QSslX509Req &req, uint32_t serial, int32_t daysStart, int32_t daysEnd);
	static QSslX509 createCA(const QSslEvpKey &caKey, const char *country, const char *province, const char *city, const char *org, const char *common, uint32_t serial, uint32_t days);
	static QByteArray publicKeyToPEM(const QSslEvpKey &key);
	static QByteArray RSAKeyToPEM(const QSslEvpKey &key);
	static QSslEvpKey pemToRSAKey(const QByteArray &pemKey);
	static QSslEvpKey pemToPublicKey(const QByteArray &pemKey);
	static QByteArray certificateToPEM(const QSslX509 &cert);
	static QSslX509 pemToCertificate(const QByteArray &pemCert);
	static QSslX509 derToCertificate(const QByteArray &derCert);
	static QByteArray certificateToDer(const QSslX509 &cert);
	static QByteArray CSRToPEM(const QSslX509Req &req);
	static QSslX509Req pemToCSR(const QByteArray &pemCSR);

	// Sha1
	static QByteArray hashAndSignSha1(const QByteArray &data, const QSslEvpKey &privateKey);
	static QByteArray signExistingSha1(QByteArray &hash, const QSslEvpKey &privateKey);
	static bool verifySignatureSha1(const QByteArray &data, QByteArray &dataSignature, const QSslEvpKey &publicKey);
	// Sha224
	static QByteArray hashAndSignSha224(const QByteArray &data, const QSslEvpKey &privateKey);
	static QByteArray signExistingSha224(QByteArray &hash, const QSslEvpKey &privateKey);
	static bool verifySignatureSha224(const QByteArray &data, QByteArray &dataSignature, const QSslEvpKey &publicKey);
	// Sha256
	static QByteArray hashAndSignSha256(const QByteArray &data, const QSslEvpKey &privateKey);
	static QByteArray signExistingSha256(QByteArray &hash, const QSslEvpKey &privateKey);
	static bool verifySignatureSha256(const QByteArray &data, QByteArray &dataSignature, const QSslEvpKey &publicKey);
	// Sha384
	static QByteArray hashAndSignSha384(const QByteArray &data, const QSslEvpKey &privateKey);
	static QByteArray signExistingSha384(QByteArray &hash, const QSslEvpKey &privateKey);
	static bool verifySignatureSha384(const QByteArray &data, QByteArray &dataSignature, const QSslEvpKey &publicKey);
	// Sha512
	static QByteArray hashAndSignSha512(const QByteArray &data, const QSslEvpKey &privateKey);
	static QByteArray signExistingSha512(QByteArray &hash, const QSslEvpKey &privateKey);
	static bool verifySignatureSha512(const QByteArray &data, QByteArray &dataSignature, const QSslEvpKey &publicKey);
	// Sha3-224
	static QByteArray hashAndSign3Sha224(const QByteArray &data, const QSslEvpKey &privateKey);
	static QByteArray signExisting3Sha224(QByteArray &hash, const QSslEvpKey &privateKey);
	static bool verifySignature3Sha224(const QByteArray &data, QByteArray &dataSignature, const QSslEvpKey &publicKey);
	// Sha3-256
	static QByteArray hashAndSign3Sha256(const QByteArray &data, const QSslEvpKey &privateKey);
	static QByteArray signExisting3Sha256(QByteArray &hash, const QSslEvpKey &privateKey);
	static bool verifySignature3Sha256(const QByteArray &data, QByteArray &dataSignature, const QSslEvpKey &publicKey);
	// Sha3-384
	static QByteArray hashAndSign3Sha384(const QByteArray &data, const QSslEvpKey &privateKey);
	static QByteArray signExisting3Sha384(QByteArray &hash, const QSslEvpKey &privateKey);
	static bool verifySignature3Sha384(const QByteArray &data, QByteArray &dataSignature, const QSslEvpKey &publicKey);
	// Sha3-512
	static QByteArray hashAndSign3Sha512(const QByteArray &data, const QSslEvpKey &privateKey);
	static QByteArray signExisting3Sha512(QByteArray &hash, const QSslEvpKey &privateKey);
	static bool verifySignature3Sha512(const QByteArray &data, QByteArray &dataSignature, const QSslEvpKey &publicKey);
	// Shake 128
	static QByteArray hashAndSignShake128(const QByteArray &data, const QSslEvpKey &privateKey);
	static QByteArray signExistingShake128(QByteArray &hash, const QSslEvpKey &privateKey);
	static bool verifySignatureShake128(const QByteArray &data, QByteArray &dataSignature, const QSslEvpKey &publicKey);
	// Shake 256
	static QByteArray hashAndSignShake256(const QByteArray &data, const QSslEvpKey &privateKey);
	static QByteArray signExistingShake256(QByteArray &hash, const QSslEvpKey &privateKey);
	static bool verifySignatureShake256(const QByteArray &data, QByteArray &dataSignature, const QSslEvpKey &publicKey);

private:
	static QSslEvpKey pemToKey(const QByteArray &pemKey, bool selectPair);
	static QByteArray hashAndSign(const EVP_MD *evp, const QByteArray &data, const QSslEvpKey &privateKey);
	static QByteArray signExistingHash(const EVP_MD *evp, QByteArray &hash, const QSslEvpKey &privateKey);
	static bool verifySignature(const EVP_MD *evp, const QByteArray &data, QByteArray &dataSignature, const QSslEvpKey &publicKey);
};


#endif
