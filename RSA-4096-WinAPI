const char* PublicKey =
"-----BEGIN RSA PUBLIC KEY-----"
""
"-----END RSA PUBLIC KEY-----";

char* b64_public_RSA_encryption(char **i_string, DWORD* b64_encrypted_size) {

	DWORD buff_len = 0, buff_b64_len = 0, dwKeySize = 0, dwParamSize = sizeof(int);
	int i = 0;  const int chunk_size = 128;
	BYTE* buff = new BYTE[0];
	char* b64_ciphertext;
	DWORD cbKeyBlob = 0;
	BYTE* pbKeyBlob = new BYTE[0];

	char ciphertext[4096] = { 0 };
	if (strlen(*i_string)<4096) { sprintf(ciphertext, "%s", *i_string);}else {return NULL;}

	HCRYPTPROV hProv;
	HCRYPTKEY hKey;

	//-------- RSA setup --------

	//get the size required for buff and put it in buff_len
	if (!CryptStringToBinaryA(PublicKey, 0, CRYPT_STRING_BASE64HEADER, NULL, &buff_len, NULL, NULL)) { goto clean_exit; }
	//allocate buff
	buff = new BYTE[buff_len];
	//convert to bytes the RSA key and put it in "buff"
	if (!CryptStringToBinaryA(PublicKey, 0, CRYPT_STRING_BASE64HEADER, buff, &buff_len, NULL, NULL)) { goto clean_exit; }

	//get the size for pbKeyBlob and put it in cbKeyBlob
	if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, buff, buff_len, 0, NULL, NULL, &cbKeyBlob)) { goto clean_exit; }
	pbKeyBlob = new BYTE[cbKeyBlob];
	//decode the previous binary buffer to a RSA key blob and put it into pbKeyBlob
	if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, buff, buff_len, 0, NULL, pbKeyBlob, &cbKeyBlob)) { goto clean_exit; }

	//get a pointer to the crypto service provider (CSP) used to call the crypto api
	if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) { goto clean_exit; }

	//import the crypto key blob inside the crypto service provider (CSP)
	if (!CryptImportKey(hProv, pbKeyBlob, cbKeyBlob, (HCRYPTKEY)NULL, 0, &hKey)) { goto clean_exit; }

	//get the key length and put it inside dwKeySize
	if (!CryptGetKeyParam(hKey, KP_KEYLEN, (BYTE*)&dwKeySize, &dwParamSize, 0)) { goto clean_exit; }

	buff_len = (DWORD)( strlen(ciphertext) * sizeof(char));

	//-------- RSA Encryption --------

	//encrypt data with hKey and put it inside enc
	if (!CryptEncrypt(hKey, 0, TRUE, 0, (BYTE*)&ciphertext, &buff_len, sizeof(ciphertext))) { goto clean_exit; }

	//ciphertext conversion [Little Endian to Big Endian] for Openssl compatibility
	dwKeySize /= 8;
	for (i = 0; i < (dwKeySize / 2); i++) {
		c = ciphertext[i];
		ciphertext[i] = ciphertext[dwKeySize - 1 - i];
		ciphertext[dwKeySize - 1 - i] = c;
	}

	//-------- BASE 64 Encoding --------

	//get b64 output length and put inside buff_b64_len
	if (!CryptBinaryToStringA((BYTE*)&ciphertext, buff_len, CRYPT_STRING_BASE64, NULL, &buff_b64_len)) { goto clean_exit; }

	//encode ciphertext to base64
	b64_ciphertext = (char*)calloc(1, buff_b64_len * sizeof(TCHAR));
	if (!CryptBinaryToStringA((BYTE*)&ciphertext, buff_len, CRYPT_STRING_BASE64, (LPSTR)b64_ciphertext, &buff_b64_len)) { goto clean_exit; }


	*i_string = b64_ciphertext;
	*b64_encrypted_size = buff_b64_len;
	
clean_exit:
	if (buff) free(buff);
	if (pbKeyBlob) free(pbKeyBlob);
	if (hKey) CryptDestroyKey(hKey);
	if (hProv) CryptReleaseContext(hProv, 0);
	return NULL;
}
