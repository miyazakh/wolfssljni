/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class com_wolfssl_WolfSSLSession */

#ifndef _Included_com_wolfssl_WolfSSLSession
#define _Included_com_wolfssl_WolfSSLSession
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    newSSL
 * Signature: (JZ)J
 */
JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_newSSL
  (JNIEnv *, jobject, jlong, jboolean);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    setFd
 * Signature: (JLjava/net/Socket;I)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setFd__JLjava_net_Socket_2I
  (JNIEnv *, jobject, jlong, jobject, jint);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    setFd
 * Signature: (JLjava/net/DatagramSocket;I)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setFd__JLjava_net_DatagramSocket_2I
  (JNIEnv *, jobject, jlong, jobject, jint);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    useCertificateFile
 * Signature: (JLjava/lang/String;I)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useCertificateFile
  (JNIEnv *, jobject, jlong, jstring, jint);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    usePrivateKeyFile
 * Signature: (JLjava/lang/String;I)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_usePrivateKeyFile
  (JNIEnv *, jobject, jlong, jstring, jint);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    useCertificateChainFile
 * Signature: (JLjava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useCertificateChainFile
  (JNIEnv *, jobject, jlong, jstring);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    setUsingNonblock
 * Signature: (JI)V
 */
JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setUsingNonblock
  (JNIEnv *, jobject, jlong, jint);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    getUsingNonblock
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getUsingNonblock
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    getFd
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getFd
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    connect
 * Signature: (JI)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_connect
  (JNIEnv *, jobject, jlong, jint);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    write
 * Signature: (J[BIII)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_write
  (JNIEnv *, jobject, jlong, jbyteArray, jint, jint, jint);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    read
 * Signature: (J[BIII)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_read__J_3BIII
  (JNIEnv *, jobject, jlong, jbyteArray, jint, jint, jint);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    read
 * Signature: (JLjava/nio/ByteBuffer;II)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_read__JLjava_nio_ByteBuffer_2II
  (JNIEnv *, jobject, jlong, jobject, jint, jint);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    accept
 * Signature: (JI)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_accept
  (JNIEnv *, jobject, jlong, jint);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    freeSSL
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_freeSSL
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    shutdownSSL
 * Signature: (JI)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_shutdownSSL
  (JNIEnv *, jobject, jlong, jint);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    getError
 * Signature: (JI)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getError
  (JNIEnv *, jobject, jlong, jint);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    setSession
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setSession
  (JNIEnv *, jobject, jlong, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    getSession
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_getSession
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    get1Session
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_get1Session
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    wolfsslSessionIsSetup
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_wolfsslSessionIsSetup
  (JNIEnv *, jclass, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    wolfsslSessionIsResumable
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_wolfsslSessionIsResumable
  (JNIEnv *, jclass, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    wolfsslSessionDup
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_wolfsslSessionDup
  (JNIEnv *, jclass, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    wolfsslSessionCipherGetName
 * Signature: (J)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_wolfsslSessionCipherGetName
  (JNIEnv *, jclass, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    freeNativeSession
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_freeNativeSession
  (JNIEnv *, jclass, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    getSessionID
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLSession_getSessionID
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    setServerID
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setServerID
  (JNIEnv *, jobject, jlong, jbyteArray, jint, jint);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    setTimeout
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setTimeout
  (JNIEnv *, jobject, jlong, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    getTimeout
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_getTimeout
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    setSessTimeout
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setSessTimeout
  (JNIEnv *, jobject, jlong, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    getSessTimeout
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_getSessTimeout
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    setCipherList
 * Signature: (JLjava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setCipherList
  (JNIEnv *, jobject, jlong, jstring);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    dtlsGetCurrentTimeout
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_dtlsGetCurrentTimeout
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    dtlsGotTimeout
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_dtlsGotTimeout
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    dtls
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_dtls
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    dtlsSetPeer
 * Signature: (JLjava/net/InetSocketAddress;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_dtlsSetPeer
  (JNIEnv *, jobject, jlong, jobject);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    dtlsGetPeer
 * Signature: (J)Ljava/net/InetSocketAddress;
 */
JNIEXPORT jobject JNICALL Java_com_wolfssl_WolfSSLSession_dtlsGetPeer
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    sessionReused
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_sessionReused
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    getPeerCertificate
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_getPeerCertificate
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    getPeerX509Issuer
 * Signature: (JJ)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_getPeerX509Issuer
  (JNIEnv *, jobject, jlong, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    getPeerX509Subject
 * Signature: (JJ)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_getPeerX509Subject
  (JNIEnv *, jobject, jlong, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    getPeerX509AltName
 * Signature: (JJ)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_getPeerX509AltName
  (JNIEnv *, jobject, jlong, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    getVersion
 * Signature: (J)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_getVersion
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    getCurrentCipher
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_getCurrentCipher
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    checkDomainName
 * Signature: (JLjava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_checkDomainName
  (JNIEnv *, jobject, jlong, jstring);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    setTmpDH
 * Signature: (J[BI[BI)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setTmpDH
  (JNIEnv *, jobject, jlong, jbyteArray, jint, jbyteArray, jint);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    setTmpDHFile
 * Signature: (JLjava/lang/String;I)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setTmpDHFile
  (JNIEnv *, jobject, jlong, jstring, jint);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    useCertificateBuffer
 * Signature: (J[BJI)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useCertificateBuffer
  (JNIEnv *, jobject, jlong, jbyteArray, jlong, jint);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    usePrivateKeyBuffer
 * Signature: (J[BJI)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_usePrivateKeyBuffer
  (JNIEnv *, jobject, jlong, jbyteArray, jlong, jint);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    useCertificateChainBuffer
 * Signature: (J[BJ)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useCertificateChainBuffer
  (JNIEnv *, jobject, jlong, jbyteArray, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    useCertificateChainBufferFormat
 * Signature: (J[BJI)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useCertificateChainBufferFormat
  (JNIEnv *, jobject, jlong, jbyteArray, jlong, jint);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    setGroupMessages
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setGroupMessages
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    enableCRL
 * Signature: (JI)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_enableCRL
  (JNIEnv *, jobject, jlong, jint);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    disableCRL
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_disableCRL
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    loadCRL
 * Signature: (JLjava/lang/String;II)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_loadCRL
  (JNIEnv *, jobject, jlong, jstring, jint, jint);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    setCRLCb
 * Signature: (JLcom/wolfssl/WolfSSLMissingCRLCallback;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setCRLCb
  (JNIEnv *, jobject, jlong, jobject);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    cipherGetName
 * Signature: (J)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_cipherGetName
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    getMacSecret
 * Signature: (JI)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLSession_getMacSecret
  (JNIEnv *, jobject, jlong, jint);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    getClientWriteKey
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLSession_getClientWriteKey
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    getClientWriteIV
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLSession_getClientWriteIV
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    getServerWriteKey
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLSession_getServerWriteKey
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    getServerWriteIV
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLSession_getServerWriteIV
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    getKeySize
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getKeySize
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    getSide
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getSide
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    isTLSv1_1
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_isTLSv1_11
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    getBulkCipher
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getBulkCipher
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    getCipherBlockSize
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getCipherBlockSize
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    getAeadMacSize
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getAeadMacSize
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    getHmacSize
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getHmacSize
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    getHmacType
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getHmacType
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    getCipherType
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getCipherType
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    setTlsHmacInner
 * Signature: (J[BJII)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setTlsHmacInner
  (JNIEnv *, jobject, jlong, jbyteArray, jlong, jint, jint);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    setEccSignCtx
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setEccSignCtx
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    setEccVerifyCtx
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setEccVerifyCtx
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    setEccSharedSecretCtx
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setEccSharedSecretCtx
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    setRsaSignCtx
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setRsaSignCtx
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    setRsaVerifyCtx
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setRsaVerifyCtx
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    setRsaEncCtx
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setRsaEncCtx
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    setRsaDecCtx
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setRsaDecCtx
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    setPskClientCb
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setPskClientCb
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    setPskServerCb
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setPskServerCb
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    getPskIdentityHint
 * Signature: (J)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_getPskIdentityHint
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    getPskIdentity
 * Signature: (J)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_getPskIdentity
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    usePskIdentityHint
 * Signature: (JLjava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_usePskIdentityHint
  (JNIEnv *, jobject, jlong, jstring);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    handshakeDone
 * Signature: (J)Z
 */
JNIEXPORT jboolean JNICALL Java_com_wolfssl_WolfSSLSession_handshakeDone
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    setConnectState
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setConnectState
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    setAcceptState
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setAcceptState
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    setVerify
 * Signature: (JILcom/wolfssl/WolfSSLVerifyCallback;)V
 */
JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setVerify
  (JNIEnv *, jobject, jlong, jint, jobject);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    setOptions
 * Signature: (JJ)J
 */
JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_setOptions
  (JNIEnv *, jobject, jlong, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    getOptions
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_getOptions
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    getShutdown
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getShutdown
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    setSSLIORecv
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setSSLIORecv
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    setSSLIOSend
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setSSLIOSend
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    useSNI
 * Signature: (JB[B)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useSNI
  (JNIEnv *, jobject, jlong, jbyte, jbyteArray);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    getSNIRequest
 * Signature: (JB)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLSession_getSNIRequest
  (JNIEnv *, jobject, jlong, jbyte);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    useSessionTicket
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useSessionTicket
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    gotCloseNotify
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_gotCloseNotify
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    sslSetAlpnProtos
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_sslSetAlpnProtos
  (JNIEnv *, jobject, jlong, jbyteArray);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    sslGet0AlpnSelected
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLSession_sslGet0AlpnSelected
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    useALPN
 * Signature: (JLjava/lang/String;I)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useALPN
  (JNIEnv *, jobject, jlong, jstring, jint);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    setALPNSelectCb
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setALPNSelectCb
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    setTls13SecretCb
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setTls13SecretCb
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    keepArrays
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_keepArrays
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    getClientRandom
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLSession_getClientRandom
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    useSecureRenegotiation
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useSecureRenegotiation
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    rehandshake
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_rehandshake
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    set1SigAlgsList
 * Signature: (JLjava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_set1SigAlgsList
  (JNIEnv *, jobject, jlong, jstring);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    useSupportedCurve
 * Signature: (JI)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useSupportedCurve
  (JNIEnv *, jobject, jlong, jint);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    hasTicket
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_hasTicket
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    interruptBlockedIO
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_interruptBlockedIO
  (JNIEnv *, jobject, jlong);

/*
 * Class:     com_wolfssl_WolfSSLSession
 * Method:    getThreadsBlockedInPoll
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getThreadsBlockedInPoll
  (JNIEnv *, jobject, jlong);

#ifdef __cplusplus
}
#endif
#endif
