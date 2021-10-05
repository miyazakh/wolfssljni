/* WolfSSLImplementSession.java
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */
package com.wolfssl.provider.jsse;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLJNIException;
import com.wolfssl.WolfSSLSession;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.X509KeyManager;

/**
 * wolfSSL Session
 * Note: suppress depreciation warning for javax.security.cert.X509Certificate
 * @author wolfSSL
 */
@SuppressWarnings("deprecation")
public class WolfSSLImplementSSLSession implements SSLSession {
    private WolfSSLSession ssl;
    private final WolfSSLAuthStore authStore;
    private WolfSSLSessionContext ctx = null;
    private boolean valid;
    private final HashMap<String, Object> binding;
    private final int port;
    private final String host;
    Date creation;
    Date accessed; /* when new connection was made using session */

    /**
     * has this session been registered
     */
    protected boolean fromTable = false;
    private long sesPtr = 0;
    private String nullCipher = "SSL_NULL_WITH_NULL_NULL";
    private String nullProtocol = "NONE";


    public WolfSSLImplementSSLSession (WolfSSLSession in, int port, String host,
            WolfSSLAuthStore params) {
        this.ssl = in;
        this.port = port;
        this.host = host;
        this.authStore = params;
        this.valid = false; /* flag if joining or resuming session is allowed */
        binding = new HashMap<String, Object>();

        creation = new Date();
        accessed = new Date();
    }

    public WolfSSLImplementSSLSession (WolfSSLSession in,
                                       WolfSSLAuthStore params) {
        this.ssl = in;
        this.port = -1;
        this.host = null;
        this.authStore = params;
        this.valid = false; /* flag if joining or resuming session is allowed */
        binding = new HashMap<String, Object>();

        creation = new Date();
        accessed = new Date();
    }

    public WolfSSLImplementSSLSession (WolfSSLAuthStore params) {
        this.port = -1;
        this.host = null;
        this.authStore = params;
        this.valid = false; /* flag if joining or resuming session is allowed */
        binding = new HashMap<String, Object>();

        creation = new Date();
        accessed = new Date();
    }

    public byte[] getId() {
        if (ssl == null) {
            return new byte[0];
        }
        return this.ssl.getSessionID();
    }

    public synchronized SSLSessionContext getSessionContext() {
        return ctx;
    }

    /**
     * Setter function for the SSLSessionContext used with session creation
     * @param ctx value to set the session context as
     */
    protected void setSessionContext(WolfSSLSessionContext ctx) {
        this.ctx = ctx;
    }

    public long getCreationTime() {
        return creation.getTime();
    }

    public long getLastAccessedTime() {
        return accessed.getTime();
    }

    public void invalidate() {
        this.valid = false;
    }

    public boolean isValid() {
        return this.valid;
    }

    /**
     * After a connection has been established or on restoring connection the session
     * is then valid and can be joined or resumed
     * @param in true/false valid boolean
     */
    protected void setValid(boolean in) {
        this.valid = in;
    }

    public void putValue(String name, Object obj) {
        Object old;

        if (name == null) {
            throw new IllegalArgumentException();
        }

        /* check if Object should be notified */
        if (obj instanceof SSLSessionBindingListener) {
            ((SSLSessionBindingListener) obj).valueBound(
                    new SSLSessionBindingEvent(this, name));
        }

        old = binding.put(name, obj);
        if (old != null) {
            if (old instanceof SSLSessionBindingListener) {
                ((SSLSessionBindingListener) old).valueUnbound(
                        new SSLSessionBindingEvent(this, name));
            }
        }
    }

    public Object getValue(String name) {
        return binding.get(name);
    }

    public void removeValue(String name) {
        Object obj;

        if (name == null) {
            throw new IllegalArgumentException();
        }

        obj = binding.get(name);
        if (obj != null) {
            /* check if Object should be notified */
            if (obj instanceof SSLSessionBindingListener) {
                ((SSLSessionBindingListener) obj).valueUnbound(
                        new SSLSessionBindingEvent(this, name));
            }
            binding.remove(name);
        }
    }

    public String[] getValueNames() {
        return binding.keySet().toArray(new String[binding.keySet().size()]);
    }

    public Certificate[] getPeerCertificates()
            throws SSLPeerUnverifiedException {
        long x509;
        WolfSSLX509 cert;

        if (ssl == null) {
            throw new SSLPeerUnverifiedException("handshake not complete");
        }

        try {
            x509 = this.ssl.getPeerCertificate();
        } catch (IllegalStateException | WolfSSLJNIException ex) {
            Logger.getLogger(
                    WolfSSLImplementSSLSession.class.getName()).log(
                        Level.SEVERE, null, ex);
            return null;
        }

        /* if no peer cert, throw SSLPeerUnverifiedException */
        if (x509 == 0) {
            throw new SSLPeerUnverifiedException("No peer certificate");
        }

        try {
            cert = new WolfSSLX509(x509);
        } catch (WolfSSLException ex) {
            throw new SSLPeerUnverifiedException("Error creating certificate");
        }

        /* convert WolfSSLX509 into X509Certificate so we can release
         * our native memory */
        CertificateFactory cf;
        ByteArrayInputStream der;
        X509Certificate exportCert;
        try {
            cf = CertificateFactory.getInstance("X.509");
        } catch (CertificateException ex) {
            cert.free();
            throw new SSLPeerUnverifiedException(
                    "Error getting CertificateFactory instance");
        }

        try {
            der = new ByteArrayInputStream(cert.getEncoded());
        } catch (CertificateEncodingException ex) {
            cert.free();
            throw new SSLPeerUnverifiedException(
                    "Error getting encoded DER from WolfSSLX509 object");
        }

        try {
            exportCert = (X509Certificate)cf.generateCertificate(der);
        } catch (CertificateException ex) {
            cert.free();
            throw new SSLPeerUnverifiedException(
                    "Error generating X509Certificdate from DER encoding");
        }

        /* release native memory */
        cert.free();

        return new Certificate[] { exportCert };
    }

    @Override
    public Certificate[] getLocalCertificates() {
        X509KeyManager km = authStore.getX509KeyManager();
        return km.getCertificateChain(authStore.getCertAlias());
    }

    @Override
<<<<<<< HEAD
    public X509Certificate[] getPeerCertificateChain()
=======
    public synchronized javax.security.cert.X509Certificate[] getPeerCertificateChain()
>>>>>>> 8483096... more diligent about feeing native certificate memory when possible
        throws SSLPeerUnverifiedException {
        WolfSSLX509X x509;

        if (ssl == null) {
            throw new SSLPeerUnverifiedException("handshake not done");
        }

        try {
            x509 = new WolfSSLX509X(this.ssl.getPeerCertificate());
            return new javax.security.cert.X509Certificate[] {
                (javax.security.cert.X509Certificate)x509 };

        } catch (IllegalStateException | WolfSSLJNIException |
                WolfSSLException ex) {
            Logger.getLogger(
                    WolfSSLImplementSSLSession.class.getName()).log(
                        Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        if (ssl == null) {
            throw new SSLPeerUnverifiedException("handshake not done");
        }

        try {
            Principal peerPrincipal = null;
            WolfSSLX509 x509 = new WolfSSLX509(this.ssl.getPeerCertificate());
            peerPrincipal = x509.getSubjectDN();
            x509.free();

            return peerPrincipal;

        } catch (IllegalStateException | WolfSSLJNIException |
                WolfSSLException ex) {
            Logger.getLogger(
                    WolfSSLImplementSSLSession.class.getName()).log(
                        Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    public Principal getLocalPrincipal() {

        X509KeyManager km = authStore.getX509KeyManager();
        java.security.cert.X509Certificate[] certs =
                km.getCertificateChain(authStore.getCertAlias());
        Principal localPrincipal = null;

        if (certs == null) {
            return null;
        }

        for (int i = 0; i < certs.length; i++) {
            if (certs[i].getBasicConstraints() < 0) {
                /* is not a CA treat as end of chain */
                localPrincipal = certs[i].getSubjectDN();
                break;
            }
        }

        /* free native resources earlier than garbage collection if
         * X509Certificate is WolfSSLX509 */
        for (int i = 0; i < certs.length; i++) {
            if (certs[i] instanceof WolfSSLX509) {
                ((WolfSSLX509)certs[i]).free();
            }
        }

        /* return principal, or null if not set */
        return localPrincipal;
    }

    @Override
    public String getCipherSuite() {
        if (ssl == null) {
            return this.nullCipher;
        }

        try {
            return this.ssl.cipherGetName();
        } catch (IllegalStateException | WolfSSLJNIException ex) {
            Logger.getLogger(
                    WolfSSLImplementSSLSession.class.getName()).log(
                        Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    public String getProtocol() {
        if (ssl == null) {
            return this.nullProtocol;
        }

        try {
            return this.ssl.getVersion();
        } catch (IllegalStateException | WolfSSLJNIException ex) {
            Logger.getLogger(
                    WolfSSLImplementSSLSession.class.getName()).log(
                        Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    public String getPeerHost() {
        return this.host;
    }

    @Override
    public int getPeerPort() {
        return this.port;
    }

    @Override
    public int getPacketBufferSize() {
        return 16394; /* 2^14, max size by standard, enum MAX_RECORD_SIZE */
    }

    @Override
    public int getApplicationBufferSize() {
        /* 16394 - (38 + 64)
         * max added to msg, mac + pad  from RECORD_HEADER_SZ + BLOCK_SZ (pad) +
         * Max digest sz + BLOC_SZ (iv) + pad byte (1)
         */
        return 16292;
    }


    /**
     * Takes in a new WOLFSSL object and sets the stored session
     * @param in WOLFSSL session to set resume in
     */
    protected void resume(WolfSSLSession in) {
        ssl = in;
        ssl.setSession(this.sesPtr);
    }


    /**
     * Should be called on shutdown to save the session pointer
     */
    protected void setResume() {
        if (ssl != null) {
            this.sesPtr = ssl.getSession();
        }
    }

    /**
     * Sets the native WOLFSSL_SESSION timeout
     * @param in timeout in seconds
     */
    protected void setNativeTimeout(long in) {
        ssl.setSessTimeout(in);
    }
}
