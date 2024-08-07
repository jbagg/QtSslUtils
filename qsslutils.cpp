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
   File name    : qsslutils.cpp
   Created      : 26 Feb 2022
   Author(s)    : Jonathan Bagg
---------------------------------------------------------------------------------------------------
   QSslUtils class definition
---------------------------------------------------------------------------------------------------
**************************************************************************************************/
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#if (OPENSSL_VERSION_MAJOR >= 3)
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#endif
#include <QDebug>
#include "qsslutils.h"

QSslEvpKey QSslUtils::generateRSAKey(uint32_t bits)
{
	QSslEvpKey publicKey;
#if (OPENSSL_VERSION_MAJOR >= 3)
	OSSL_LIB_CTX *sslLibContext = nullptr;
	publicKey = QSslEvpKey(EVP_PKEY_Q_keygen(sslLibContext, nullptr, "RSA", bits), [](EVP_PKEY *x) { EVP_PKEY_free(x); });
	OSSL_LIB_CTX_free(sslLibContext);
#else
	RSA *rsa = nullptr;
	std::unique_ptr<BIGNUM, std::function<void (BIGNUM *)>> bne(BN_new(), [](BIGNUM *b) { BN_free(b); });
	if (BN_set_word(bne.get(), RSA_F4) != 1) {
		return publicKey;
	}

	rsa = RSA_new();
	if (RSA_generate_key_ex(rsa, bits, bne.get(), nullptr) != 1) {
		RSA_free(rsa);  // EVP_PKEY_assign_RSA takes ownership of the rsa key.  Only need to delete here if failure.
		return publicKey;
	}

	publicKey = QSslEvpKey(EVP_PKEY_new(), [](EVP_PKEY *x) { EVP_PKEY_free(x); });
	if (!publicKey)
		return publicKey;
	EVP_PKEY_assign_RSA(publicKey.data(), rsa);
#endif
	return publicKey;
}

QSslX509Req QSslUtils::createCSR(const QSslEvpKey &publicKey, const char *country, const char *province, const char *city, const char *org, const char *common)
{
	QSslX509Req x509Req(X509_REQ_new(), [](X509_REQ *req) { X509_REQ_free(req); });
	X509_NAME *name = nullptr;

	if (publicKey.isNull()) {
		qDebug("QSslUtils::createCSR - passed Key is null");
		x509Req.clear();
		return x509Req;
	}

	if (!X509_REQ_set_version(x509Req.data(), 0)) {
		x509Req.clear();
		return x509Req;
	}

	name = X509_REQ_get_subject_name(x509Req.data());

	if (!X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (uint8_t *)country, -1, -1, 0)) {
		qDebug("QSslUtils::createCSR - setting country failed - is more than 2 digits?");
		x509Req.clear();
		return x509Req;
	}
	if (!X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (uint8_t *)province, -1, -1, 0)) {
		x509Req.clear();
		return x509Req;
	}
	if (!X509_NAME_add_entry_by_txt(name,"L", MBSTRING_ASC, (uint8_t *)city, -1, -1, 0)) {
		x509Req.clear();
		return x509Req;
	}
	if (!X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (uint8_t *)org, -1, -1, 0)) {
		x509Req.clear();
		return x509Req;
	}
	if (!X509_NAME_add_entry_by_txt(name,"CN", MBSTRING_ASC, (uint8_t *)common, -1, -1, 0)) {
		x509Req.clear();
		return x509Req;
	}
	if (!X509_REQ_set_pubkey(x509Req.data(), publicKey.data())) {
		x509Req.clear();
		return x509Req;
	}
	if (!X509_REQ_sign(x509Req.data(), publicKey.data(), EVP_sha256())) {
		x509Req.clear();
		return x509Req;
	}

	return x509Req;
}

QSslX509 QSslUtils::signCSR(const QSslX509 &ca, const QSslEvpKey &caKey, const QSslX509Req &req, uint32_t serial, int32_t daysStart, int32_t daysEnd)
{
	QSslX509 newCert(X509_new(), [](X509 *cert) { X509_free(cert); });

	if (ca.isNull() || caKey.isNull() || req.isNull()) {
		qDebug("QSslUtils::signCSR - null input");
		newCert.clear();
		return newCert;
	}

	if (!X509_set_version(newCert.data(), 0)) {
		newCert.clear();
		return newCert;
	}
	if (!ASN1_INTEGER_set_int64(X509_get_serialNumber(newCert.data()), serial)) {
		newCert.clear();
		return newCert;
	}
	if (!X509_set_issuer_name(newCert.data(), X509_get_subject_name(ca.data()))) {
		newCert.clear();
		return newCert;
	}

	X509_gmtime_adj(X509_getm_notBefore(newCert.data()), (long)3600 * 24 * daysStart);
	X509_gmtime_adj(X509_getm_notAfter(newCert.data()), (long)3600 * 24 * daysEnd);

	if (!X509_set_subject_name(newCert.data(), X509_REQ_get_subject_name(req.data()))) {
		newCert.clear();
		return newCert;
	}

	std::unique_ptr<EVP_PKEY, std::function<void (EVP_PKEY *)>> csrPubkey(X509_REQ_get_pubkey(req.data()), [](EVP_PKEY *key) { EVP_PKEY_free(key); });
	if (!X509_set_pubkey(newCert.data(), csrPubkey.get())) {
		newCert.clear();
		return newCert;
	}

	if (!X509_sign(newCert.data(), caKey.data(), EVP_sha256())) {
		newCert.clear();
		return newCert;
	}

	return newCert;
}

QSslX509 QSslUtils::createCA(const QSslEvpKey &pk, const char *country, const char *province, const char *city, const char *org, const char *common, uint32_t serial, uint32_t days)
{
	QSslX509 ca(X509_new(), [](X509 *cert) { X509_free(cert); });
	X509_NAME *name = nullptr;

	if (pk.isNull()) {
		qDebug("QSslUtils::createCA - passed Key is null");
		ca.clear();
		return ca;
	}

	if (!X509_set_version(ca.data(), 2)) {
		ca.clear();
		return ca;
	}
	if (!ASN1_INTEGER_set_int64(X509_get_serialNumber(ca.data()), serial)) {
		ca.clear();
		return ca;
	}
	if (!X509_gmtime_adj(X509_getm_notBefore(ca.data()), 0)) {
		ca.clear();
		return ca;
	}
	if (!X509_gmtime_adj(X509_getm_notAfter(ca.data()), (long)3600 * 24 * days)) {
		ca.clear();
		return ca;
	}
	if (!X509_set_pubkey(ca.data(), pk.data())) {
		ca.clear();
		return ca;
	}

	name = X509_get_subject_name(ca.data());

	if (!X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (uint8_t *)country, -1, -1, 0)) {
		qDebug("QSslUtils::createCA - setting country failed - is more than 2 digits?");
		ca.clear();
		return ca;
	}
	if (!X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (uint8_t *)province, -1, -1, 0)) {
		ca.clear();
		return ca;
	}
	if (!X509_NAME_add_entry_by_txt(name,"L", MBSTRING_ASC, (uint8_t *)city, -1, -1, 0)) {
		ca.clear();
		return ca;
	}
	if (!X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (uint8_t *)org, -1, -1, 0)) {
		ca.clear();
		return ca;
	}
	if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (uint8_t *)common, -1, -1, 0)) {
		ca.clear();
		return ca;
	}

	// self signed --> issuer name = subject
	if (!X509_set_issuer_name(ca.data(), name)) {
		ca.clear();
		return ca;
	}

	auto addExtension = [](X509 *cert, int nid, char *value) {
		X509_EXTENSION *ext;
		X509V3_CTX ctx;

		X509V3_set_ctx_nodb(&ctx);
		X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);
		ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
		if (!ext)
			return false;

		X509_add_ext(cert, ext, -1);
		X509_EXTENSION_free(ext);
		return true;
	};

	// Add extensions
	if (!addExtension(ca.data(), NID_basic_constraints, (char *) "critical,CA:TRUE")) {
		ca.clear();
		return ca;
	}
	if (!addExtension(ca.data(), NID_key_usage, (char *) "critical,keyCertSign,cRLSign")) {
		ca.clear();
		return ca;
	}
	if (!addExtension(ca.data(), NID_subject_key_identifier, (char *) "hash")) {
		ca.clear();
		return ca;
	}

	if (!X509_sign(ca.data(), pk.data(), EVP_sha256()))
		ca.clear();

	return ca;
}

QByteArray QSslUtils::publicKeyToPEM(const QSslEvpKey &key)
{
	QByteArray keyByteArray;
	std::unique_ptr<BIO, std::function<void (BIO *)>> keyBIO(BIO_new(BIO_s_mem()), [](BIO *bio) { BIO_free_all(bio); });
	PEM_write_bio_PUBKEY(keyBIO.get(), key.data());
	keyByteArray.resize(BIO_pending(keyBIO.get()) + 1);
	BIO_read(keyBIO.get(), keyByteArray.data(), keyByteArray.size() - 1);
	return keyByteArray;
}

QByteArray QSslUtils::RSAKeyToPEM(const QSslEvpKey &key)
{
	QByteArray keyByteArray;

#if (OPENSSL_VERSION_MAJOR >= 3)
	OSSL_ENCODER_CTX *enc;
	std::unique_ptr<BIO, std::function<void (BIO *)>> keyBIO(BIO_new(BIO_s_mem()), [](BIO *bio) { BIO_free_all(bio); });
	enc = OSSL_ENCODER_CTX_new_for_pkey(key.data(), OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, "PEM", "PrivateKeyInfo", nullptr);
	if (OSSL_ENCODER_to_bio(enc, keyBIO.get())) {
		keyByteArray.resize(BIO_pending(keyBIO.get()) + 1);
		BIO_read(keyBIO.get(), keyByteArray.data(), keyByteArray.size() - 1);
	}
	OSSL_ENCODER_CTX_free(enc);
#else
	RSA *rsa = EVP_PKEY_get0_RSA(key.data());
	std::unique_ptr<BIO, std::function<void (BIO *)>> keyBIO(BIO_new(BIO_s_mem()), [](BIO *bio) { BIO_free_all(bio); });
	PEM_write_bio_RSAPrivateKey(keyBIO.get(), rsa, nullptr, nullptr, RSA_size(rsa), nullptr, nullptr);
	keyByteArray.resize(BIO_pending(keyBIO.get()) + 1);
	BIO_read(keyBIO.get(), keyByteArray.data(), keyByteArray.size() - 1);
#endif
	return keyByteArray;
}

QSslEvpKey QSslUtils::pemToKey(const QByteArray &pemKey, bool selectPair)
{
	QSslEvpKey key;

#if (OPENSSL_VERSION_MAJOR >= 3)
	EVP_PKEY *evpPkey = nullptr;
	int keyTypeFlags = 0;
	if (selectPair)
		keyTypeFlags = OSSL_KEYMGMT_SELECT_KEYPAIR;
	else
		keyTypeFlags = OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
	std::unique_ptr<BIO, std::function<void (BIO *)>> keyBIO(BIO_new_mem_buf(pemKey.data(), -1), [](BIO *bio) { BIO_free_all(bio); });
	OSSL_DECODER_CTX *dec = OSSL_DECODER_CTX_new_for_pkey(&evpPkey, "PEM", nullptr, "RSA", keyTypeFlags, nullptr, nullptr);
	if (OSSL_DECODER_from_bio(dec, keyBIO.get()))
		key = QSslEvpKey(evpPkey, [](EVP_PKEY *x) { EVP_PKEY_free(x); });
	OSSL_DECODER_CTX_free(dec);
#else
	RSA *rsa;
	std::unique_ptr<BIO, std::function<void (BIO *)>> certBIO(BIO_new_mem_buf(pemKey.data(), -1), [](BIO *bio) { BIO_free_all(bio); });
	if (selectPair)
		rsa = PEM_read_bio_RSAPrivateKey(certBIO.get(), nullptr, nullptr, nullptr);
	else
		rsa = PEM_read_bio_RSAPublicKey(certBIO.get(), nullptr, nullptr, nullptr);
	if (!rsa)
		return key;

	key = QSslEvpKey(EVP_PKEY_new(), [](EVP_PKEY *x) { EVP_PKEY_free(x); });
	if (!key)
		return key;
	EVP_PKEY_assign_RSA(key.data(), rsa);
#endif
	return key;
}

QSslEvpKey QSslUtils::pemToRSAKey(const QByteArray &pemKey)
{
	return pemToKey(pemKey, true);
}

QSslEvpKey QSslUtils::pemToPublicKey(const QByteArray &pemKey)
{
	return pemToKey(pemKey, false);
}

QByteArray QSslUtils::certificateToPEM(const QSslX509 &cert)
{
	QByteArray certByteArray;
	std::unique_ptr<BIO, std::function<void (BIO *)>> certBIO(BIO_new(BIO_s_mem()), [](BIO *bio) { BIO_free_all(bio); });
	PEM_write_bio_X509(certBIO.get(), cert.data());
	certByteArray.resize(BIO_pending(certBIO.get()) + 1);
	BIO_read(certBIO.get(), certByteArray.data(), certByteArray.size() - 1);
	return certByteArray;
}

QSslX509 QSslUtils::pemToCertificate(const QByteArray &pemCert)
{
	std::unique_ptr<BIO, std::function<void (BIO *)>> certBIO(BIO_new_mem_buf(pemCert.data(), -1), [](BIO *bio) { BIO_free_all(bio); });
	return QSslX509(PEM_read_bio_X509(certBIO.get(), nullptr, nullptr, nullptr), [](X509 *cert) { X509_free(cert); });
}

QSslX509 QSslUtils::derToCertificate(const QByteArray &derCert)
{
	const unsigned char *data;
	data = reinterpret_cast<const unsigned char *>(derCert.data());
	return QSslX509(d2i_X509(nullptr, &data, derCert.size()), [](X509 *cert) { X509_free(cert); });
}

QByteArray QSslUtils::certificateToDer(const QSslX509 &cert)
{
	unsigned char *data = nullptr;
	ssize_t size = i2d_X509(cert.data(), &data);
	QByteArray certByteArray(reinterpret_cast<char *>(data), size);
	free(data);
	return certByteArray;
}

QByteArray QSslUtils::CSRToPEM(const QSslX509Req &req)
{
	QByteArray csrByteArray;
	std::unique_ptr<BIO, std::function<void (BIO *)>> certBIO(BIO_new(BIO_s_mem()), [](BIO *bio) { BIO_free_all(bio); });
	PEM_write_bio_X509_REQ(certBIO.get(), req.data());
	csrByteArray.resize(BIO_pending(certBIO.get()) + 1);
	BIO_read(certBIO.get(), csrByteArray.data(), csrByteArray.size() - 1);
	return csrByteArray;
}

QSslX509Req QSslUtils::pemToCSR(const QByteArray &pemCSR)
{
	std::unique_ptr<BIO, std::function<void (BIO *)>> certBIO(BIO_new_mem_buf(pemCSR.data(), -1), [](BIO *bio) { BIO_free_all(bio); });
	return QSslX509Req(PEM_read_bio_X509_REQ(certBIO.get(), nullptr, nullptr, nullptr), [](X509_REQ *csr) { X509_REQ_free(csr); });
}

QByteArray QSslUtils::hashAndSign(const EVP_MD *evp, const QByteArray &data, const QSslEvpKey &privateKey)
{
	QByteArray signature;
	size_t signatureLength;
	EVP_MD_CTX *evpMdContext = EVP_MD_CTX_create();

	EVP_DigestSignInit(evpMdContext, nullptr, evp, nullptr, privateKey.data());
	EVP_DigestSignUpdate(evpMdContext, data.data(), data.length());
	EVP_DigestSignFinal(evpMdContext, nullptr, &signatureLength);
	signature.resize(signatureLength);
	EVP_DigestSignFinal(evpMdContext, reinterpret_cast<unsigned char *>(signature.data()), &signatureLength);

	EVP_MD_CTX_destroy(evpMdContext);

	return signature;
}

QByteArray QSslUtils::signExistingHash(const EVP_MD *evp, QByteArray &hash, const QSslEvpKey &privateKey)
{
	QByteArray signature;
	size_t sigOutLength;
	size_t inSize = hash.size();

#if (OPENSSL_VERSION_MAJOR >= 3)
	EVP_PKEY_CTX *pkeyContext = EVP_PKEY_CTX_new_from_pkey(nullptr, privateKey.data(), "");
#else
	EVP_PKEY_CTX *pkeyContext = EVP_PKEY_CTX_new(privateKey.data(), nullptr);
#endif
	EVP_PKEY_sign_init(pkeyContext);
	EVP_PKEY_CTX_set_signature_md(pkeyContext, evp);
	EVP_PKEY_sign(pkeyContext, nullptr, &sigOutLength, reinterpret_cast<unsigned char *>(hash.data()), inSize);
	signature.resize(sigOutLength);
	EVP_PKEY_sign(pkeyContext, reinterpret_cast<unsigned char *>(signature.data()), &sigOutLength, reinterpret_cast<unsigned char *>(hash.data()), inSize);
	EVP_PKEY_CTX_free(pkeyContext);
	return signature;
}

bool QSslUtils::verifySignature(const EVP_MD *evp, const QByteArray &data, QByteArray &dataSignature, const QSslEvpKey &publicKey)
{
	EVP_MD_CTX* evpMdContext = EVP_MD_CTX_create();
	bool matches = false;

	EVP_DigestVerifyInit(evpMdContext, nullptr, evp, nullptr, publicKey.data());
	EVP_DigestVerifyUpdate(evpMdContext, data.data(), data.length());
	if (EVP_DigestVerifyFinal(evpMdContext, reinterpret_cast<unsigned char *>(dataSignature.data()), static_cast<size_t>(dataSignature.length())) == 1)
		matches = true;

	EVP_MD_CTX_destroy(evpMdContext);

	return matches;
}

QByteArray QSslUtils::hashAndSignSha1(const QByteArray &data, const QSslEvpKey &privateKey)
{
	return hashAndSign(EVP_sha1(), data, privateKey);
}

QByteArray QSslUtils::signExistingSha1(QByteArray &hash, const QSslEvpKey &privateKey)
{
	return signExistingHash(EVP_sha1(), hash, privateKey);
}

bool QSslUtils::verifySignatureSha1(const QByteArray &data, QByteArray &dataSignature, const QSslEvpKey &publicKey)
{
	return verifySignature(EVP_sha1(), data, dataSignature, publicKey);
}

QByteArray QSslUtils::hashAndSignSha224(const QByteArray &data, const QSslEvpKey &privateKey)
{
	return hashAndSign(EVP_sha224(), data, privateKey);
}

QByteArray QSslUtils::signExistingSha224(QByteArray &hash, const QSslEvpKey &privateKey)
{
	return signExistingHash(EVP_sha224(), hash, privateKey);
}

bool QSslUtils::verifySignatureSha224(const QByteArray &data, QByteArray &dataSignature, const QSslEvpKey &publicKey)
{
	return verifySignature(EVP_sha224(), data, dataSignature, publicKey);
}

QByteArray QSslUtils::hashAndSignSha256(const QByteArray &data, const QSslEvpKey &privateKey)
{
	return hashAndSign(EVP_sha256(), data, privateKey);
}

QByteArray QSslUtils::signExistingSha256(QByteArray &hash, const QSslEvpKey &privateKey)
{
	return signExistingHash(EVP_sha256(), hash, privateKey);
}

bool QSslUtils::verifySignatureSha256(const QByteArray &data, QByteArray &dataSignature, const QSslEvpKey &publicKey)
{
	return verifySignature(EVP_sha256(), data, dataSignature, publicKey);
}

QByteArray QSslUtils::hashAndSignSha384(const QByteArray &data, const QSslEvpKey &privateKey)
{
	return hashAndSign(EVP_sha384(), data, privateKey);
}

QByteArray QSslUtils::signExistingSha384(QByteArray &hash, const QSslEvpKey &privateKey)
{
	return signExistingHash(EVP_sha384(), hash, privateKey);
}

bool QSslUtils::verifySignatureSha384(const QByteArray &data, QByteArray &dataSignature, const QSslEvpKey &publicKey)
{
	return verifySignature(EVP_sha384(), data, dataSignature, publicKey);
}

QByteArray QSslUtils::hashAndSignSha512(const QByteArray &data, const QSslEvpKey &privateKey)
{
	return hashAndSign(EVP_sha512(), data, privateKey);
}

QByteArray QSslUtils::signExistingSha512(QByteArray &hash, const QSslEvpKey &privateKey)
{
	return signExistingHash(EVP_sha512(), hash, privateKey);
}

bool QSslUtils::verifySignatureSha512(const QByteArray &data, QByteArray &dataSignature, const QSslEvpKey &publicKey)
{
	return verifySignature(EVP_sha512(), data, dataSignature, publicKey);
}

QByteArray QSslUtils::hashAndSign3Sha224(const QByteArray &data, const QSslEvpKey &privateKey)
{
	return hashAndSign(EVP_sha3_224(), data, privateKey);
}

QByteArray QSslUtils::signExisting3Sha224(QByteArray &hash, const QSslEvpKey &privateKey)
{
	return signExistingHash(EVP_sha3_224(), hash, privateKey);
}

bool QSslUtils::verifySignature3Sha224(const QByteArray &data, QByteArray &dataSignature, const QSslEvpKey &publicKey)
{
	return verifySignature(EVP_sha3_224(), data, dataSignature, publicKey);
}

QByteArray QSslUtils::hashAndSign3Sha256(const QByteArray &data, const QSslEvpKey &privateKey)
{
	return hashAndSign(EVP_sha3_256(), data, privateKey);
}

QByteArray QSslUtils::signExisting3Sha256(QByteArray &hash, const QSslEvpKey &privateKey)
{
	return signExistingHash(EVP_sha3_256(), hash, privateKey);
}

bool QSslUtils::verifySignature3Sha256(const QByteArray &data, QByteArray &dataSignature, const QSslEvpKey &publicKey)
{
	return verifySignature(EVP_sha3_256(), data, dataSignature, publicKey);
}

QByteArray QSslUtils::hashAndSign3Sha384(const QByteArray &data, const QSslEvpKey &privateKey)
{
	return hashAndSign(EVP_sha3_384(), data, privateKey);
}

QByteArray QSslUtils::signExisting3Sha384(QByteArray &hash, const QSslEvpKey &privateKey)
{
	return signExistingHash(EVP_sha3_384(), hash, privateKey);
}

bool QSslUtils::verifySignature3Sha384(const QByteArray &data, QByteArray &dataSignature, const QSslEvpKey &publicKey)
{
	return verifySignature(EVP_sha3_384(), data, dataSignature, publicKey);
}

QByteArray QSslUtils::hashAndSign3Sha512(const QByteArray &data, const QSslEvpKey &privateKey)
{
	return hashAndSign(EVP_sha3_512(), data, privateKey);
}

QByteArray QSslUtils::signExisting3Sha512(QByteArray &hash, const QSslEvpKey &privateKey)
{
	return signExistingHash(EVP_sha3_512(), hash, privateKey);
}

bool QSslUtils::verifySignature3Sha512(const QByteArray &data, QByteArray &dataSignature, const QSslEvpKey &publicKey)
{
	return verifySignature(EVP_sha3_512(), data, dataSignature, publicKey);
}

QByteArray QSslUtils::hashAndSignShake128(const QByteArray &data, const QSslEvpKey &privateKey)
{
	return hashAndSign(EVP_shake128(), data, privateKey);
}

QByteArray QSslUtils::signExistingShake128(QByteArray &hash, const QSslEvpKey &privateKey)
{
	return signExistingHash(EVP_shake128(), hash, privateKey);
}

bool QSslUtils::verifySignatureShake128(const QByteArray &data, QByteArray &dataSignature, const QSslEvpKey &publicKey)
{
	return verifySignature(EVP_shake128(), data, dataSignature, publicKey);
}

QByteArray QSslUtils::hashAndSignShake256(const QByteArray &data, const QSslEvpKey &privateKey)
{
	return hashAndSign(EVP_shake256(), data, privateKey);
}

QByteArray QSslUtils::signExistingShake256(QByteArray &hash, const QSslEvpKey &privateKey)
{
	return signExistingHash(EVP_shake256(), hash, privateKey);
}

bool QSslUtils::verifySignatureShake256(const QByteArray &data, QByteArray &dataSignature, const QSslEvpKey &publicKey)
{
	return verifySignature(EVP_shake256(), data, dataSignature, publicKey);
}
