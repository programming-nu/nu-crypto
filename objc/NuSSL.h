/*!
 @file NuSSL.h
 @copyright Copyright (c) 2013 Radtastical, Inc.
 
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 
 http://www.apache.org/licenses/LICENSE-2.0
 
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */
#ifdef NuCrypto_OpenSSL

// WARNING - EVERYTHING IN THIS FILE IS EXPERIMENTAL JUNK AND SUBJECT TO CHANGE

// since this requires OpenSSL, we omit it from iPhone builds
#if !TARGET_OS_IPHONE

@interface NuSSL : NSObject

- (void) setCAListFileName:(NSString *)CAListFileName;
- (void) setCAListData:(NSData *) cert_data;
- (void) setCAListText:(NSString *) cert_string;

- (void) setCertificateFileName:(NSString *)certificateFileName;
- (void) setCertificateData:(NSData *) cert_data;
- (void) setCertificateText:(NSString *) cert_string;

- (void) setKeyFileName:(NSString *)keyFileName;
- (void) setKeyData:(NSData *) key_data;
- (void) setKeyText:(NSString *) key_string;

- (BOOL) sendPayload:(NSString *) payloadString toDeviceWithToken:(NSString *) deviceTokenString;
- (void) connectToHost:(NSString *) host port:(int) port;
- (void) closeConnection;

@end

@interface NSData (NuSSL)
+ (NSData *) dataWithBIO:(BIO *) bio;
@end

@interface NuRSAKey : NSObject {
@public
    RSA *rsa;
}
- (id) initWithPrivateKeyData:(NSData *) key_data;
- (id) initWithPrivateKeyText:(NSString *) key_string;
- (int) checkKey;
@end

@interface NuEVPPKey : NSObject {
@public
    EVP_PKEY *pkey;
}
- (id) initWithRSAKey:(NuRSAKey *) rsaKey;
@end

@interface NuX509Request : NSObject {
    X509_REQ *req;
}
@end

@interface NuX509Certificate : NSObject {
@public
    X509 *cert;
}
- (id) initWithData:(NSData *) cert_data;
- (id) initWithText:(NSString *) cert_string;
- (id) initWithX509:(X509 *) x509;
- (NSString *) name;
- (NSData *) dataRepresentation;
- (NSString *) textRepresentation;
@end

@interface NuPKCS7Message : NSObject {
@public
    PKCS7 *p7;
}

+ (void) initialize;
+ (NuPKCS7Message *) signedMessageWithCertificate:(NuX509Certificate *) certificate
                                        privateKey:(NuEVPPKey *) key
                                              data:(NSData *) dataToSign
                                  signedAttributes:(NSDictionary *) signedAttributes;
+ (NuPKCS7Message *) degenerateWrapperForCertificate:(NuX509Certificate *) certificate;
+ (NuPKCS7Message *) encryptedMessageWithCertificates:(NSArray *) certificates
                                                  data:(NSData *) dataToEncrypt;
- (id) initWithData:(NSData *) data;
- (id) initWithPKCS7:(PKCS7 *) pkcs7;
- (NSData *) dataRepresentation;
- (NSString *) textRepresentation;
- (NSData *) decryptWithKey:(NuEVPPKey *) key
                certificate:(NuX509Certificate *) certificate;
- (NuX509Certificate *) signerCertificate;
- (NSDictionary *) attributes;
- (NSData *) verifyWithCertificate:(NuX509Certificate *) certificate;
@end

@interface NuCertificateAuthority : NSObject

- (NuX509Certificate *) generateCertificateForRequest:(NSData *) requestData
                                     withCACertificate:(NuX509Certificate *) caCertificate
                                            privateKey:(NuEVPPKey *) caPrivateKey;
@end

#endif
#endif
