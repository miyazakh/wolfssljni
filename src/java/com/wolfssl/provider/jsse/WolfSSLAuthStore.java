/* WolfSSLAuthStore.java
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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
import com.wolfssl.WolfSSLSession;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.security.KeyStore;
import java.security.SecureRandom;

import java.security.KeyStoreException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Helper class used to store common settings, objects, etc.
 */
public class WolfSSLAuthStore {

    static enum TLS_VERSION {
        INVALID,
        TLSv1,
        TLSv1_1,
        TLSv1_2,
        TLSv1_3,
        SSLv23
    }

    private TLS_VERSION currentVersion = TLS_VERSION.INVALID;

    private X509KeyManager km = null;
    private X509TrustManager tm = null;
    private SecureRandom sr = null;
    private String alias = null;
    private WolfSSLSessionContext serverCtx = null;
    private WolfSSLSessionContext clientCtx = null;

    private SessionStore<Integer, WolfSSLImplementSSLSession> store = null;
    private static final Object storeLock = new Object();

    /**
     * Protected constructor to create new WolfSSLAuthStore
     * @param keyman key manager to use
     * @param trustman trust manager to use
     * @param random secure random
     * @param version TLS protocol version to use
     * @throws IllegalArgumentException when bad values are passed in
     * @throws KeyManagementException in the case that getting keys fails
     */
    protected WolfSSLAuthStore(KeyManager[] keyman, TrustManager[] trustman,
        SecureRandom random, TLS_VERSION version)
        throws IllegalArgumentException, KeyManagementException {
            int defaultCacheSize = 10;

        if (version == TLS_VERSION.INVALID) {
            throw new IllegalArgumentException("Invalid SSL/TLS version");
        }

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "Creating new WolfSSLAuthStore");

        initKeyManager(keyman);
        initTrustManager(trustman);
        initSecureRandom(random);

        this.currentVersion = version;
        store = new SessionStore<Integer,
                                 WolfSSLImplementSSLSession>(defaultCacheSize);
        this.serverCtx = new WolfSSLSessionContext(this, defaultCacheSize);
        this.clientCtx = new WolfSSLSessionContext(this, defaultCacheSize);
    }

    /**
     * Initialize key manager.
     * The first instance of X509KeyManager found will be used. If null is
     * passed in, installed security providers with be searched for highest
     * priority implementation of the required factory.
     */
    private void initKeyManager(KeyManager[] in)
        throws KeyManagementException {
        KeyManager[] managers = in;
        if (managers == null || managers.length == 0) {
            try {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "searching installed providers for X509KeyManager");

                /* use key managers from installed security providers */
                KeyManagerFactory kmFactory = KeyManagerFactory.getInstance(
                    KeyManagerFactory.getDefaultAlgorithm());
                kmFactory.init(null, null);
                managers = kmFactory.getKeyManagers();

            } catch (NoSuchAlgorithmException nsae) {
                throw new KeyManagementException(nsae);
            } catch (KeyStoreException kse) {
                throw new KeyManagementException(kse);
            } catch (UnrecoverableKeyException uke) {
                throw new KeyManagementException(uke);
            }
        }

        if (managers != null) {
            for (int i = 0; i < managers.length; i++) {
                if (managers[i] instanceof X509KeyManager) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "located X509KeyManager instance");
                    km = (X509KeyManager)managers[i];
                    break;
                }
            }
        }
    }

    /**
     * Initialize trust manager.
     * The first instance of X509TrustManager found will be used. If null is
     * passed in, installed security providers with be searched for highest
     * priority implementation of the required factory.
     */
    private void initTrustManager(TrustManager[] in)
        throws KeyManagementException {
        TrustManager[] managers = in;
        if (managers == null || managers.length == 0) {

            try {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "searching installed providers for X509TrustManager");

                /* use trust managers from installed security providers */
                TrustManagerFactory tmFactory = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
                tmFactory.init((KeyStore)null);
                managers = tmFactory.getTrustManagers();

            } catch (NoSuchAlgorithmException nsae) {
                throw new KeyManagementException(nsae);
            } catch (KeyStoreException kse) {
                throw new KeyManagementException(kse);
            }
        }

        if (managers != null) {
            for (int i = 0; i < managers.length; i++) {
                if (managers[i] instanceof X509TrustManager) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "located X509TrustManager instance");
                    tm = (X509TrustManager)managers[i];
                    break;
                }
            }
        }
    }

    /**
     * Initialize secure random.
     * If SecureRandom passed in is null, default implementation will
     * be used.
     */
    private void initSecureRandom(SecureRandom random) {

        if (random == null) {
            sr = new SecureRandom();
        }
        sr = random;
    }


    /**
     * @return get the key manager used
     */
    protected X509KeyManager getX509KeyManager() {
        return this.km;
    }

    /**
     * @return get the trust manager used
     */
    protected X509TrustManager getX509TrustManager() {
        return this.tm;
    }

    /**
     * @return get secure random
     */
    protected SecureRandom getSecureRandom() {
        return this.sr;
    }

    /**
     * @return get the current protocol version set
     */
    protected TLS_VERSION getProtocolVersion() {
        return this.currentVersion;
    }

    /**
     * @param in alias to set for certificate used
     */
    protected void setCertAlias(String in) {
        this.alias = in;
    }

    /**
     * @return alias name
     */
    protected String getCertAlias() {
        return this.alias;
    }


    /**
     * Getter function for WolfSSLSessionContext associated with store
     * @return pointer to the context set
     */
    protected WolfSSLSessionContext getServerContext() {
        return this.serverCtx;
    }


    /**
     * Getter function for WolfSSLSessionContext associated with store
     * @return pointer to the context set
     */
    protected WolfSSLSessionContext getClientContext() {
        return this.clientCtx;
    }


    /**
     * Reset the size of the array to cache sessions
     * @param sz new array size
     */
    protected void resizeCache(int sz) {
            SessionStore<Integer, WolfSSLImplementSSLSession> newStore =
                    new SessionStore<Integer, WolfSSLImplementSSLSession>(sz);

        store.putAll(newStore);
        store = newStore;
    }

    /** Returns either an existing session to use or creates a new session. Can
     * return null on error case or the case where session could not be created.
     * @param ssl WOLFSSL class to set in session
     * @param port port number connecting to
     * @param host host connecting to
     * @param clientMode if is client side then true
     * @return a new or reused SSLSession on success, null on failure
     */
    protected WolfSSLImplementSSLSession getSession(WolfSSLSession ssl,
        int port, String host, boolean clientMode) {

        WolfSSLImplementSSLSession ses = null;
        String toHash = null;

        if (ssl == null) {
            return null;
        }

        /* server mode, or client mode with no host */
        if (clientMode == false || host == null) {
            return this.getSession(ssl);
        }
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "attempting to look up session (" +
                "host: " + host + ", port: " + port + ")");

        /* Lock on static/global storeLock, since Java session cache table
         * is shared between all threads */
        synchronized (storeLock) {

            /* generate cache key hash (host:port) */
            toHash = host.concat(Integer.toString(port));

            /* try getting session out of Java store */
            ses = store.get(toHash.hashCode());

            if (ses == null) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "session not found in cache table, creating new");
                /* not found in stored sessions create a new one */
                ses = new WolfSSLImplementSSLSession(ssl, port, host, this);
                ses.setValid(true); /* new sessions marked as valid */
                ses.isFromTable = false;
                ses.setPseudoSessionId(
                    Integer.toString(ssl.hashCode()).getBytes());
            }
            else {
                /* Remove old entry from table. TLS 1.3 binder changes between
                 * resumptions and stored session should only be used to
                 * resume once. New session structure/object will be cached
                 * after the resumed session completes the handshake, for
                 * subsequent resumption attempts to use. */
                store.remove(toHash.hashCode());
                ses.isFromTable = true;

                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "session found in cache, trying to resume");
                ses.resume(ssl);
            }
            return ses;
        }
    }

    /** Returns a new session, does not check/save for resumption
     * @param ssl WOLFSSL class to reference with new session
     * @return a new SSLSession on success
     */
    protected WolfSSLImplementSSLSession getSession(WolfSSLSession ssl) {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "creating new session");
        WolfSSLImplementSSLSession ses = new WolfSSLImplementSSLSession(ssl, this);
        if (ses != null) {
            ses.setValid(true);
            ses.isFromTable = false;
            ses.setPseudoSessionId(Integer.toString(ssl.hashCode()).getBytes());
            if (ssl.getSide() == WolfSSL.WOLFSSL_SERVER_END) {
                ses.setSessionContext(serverCtx);
            }
            else {
                ses.setSessionContext(clientCtx);
            }
        }
        return ses;
    }

    /**
     * Internal helper function to check if session ID is all zeros.
     * Used by addSession()
     *
     * @param id session ID
     * @return true if array is all zeros (0x00), otherwise false
     */
    private boolean idAllZeros(byte[] id) {
        boolean ret = true;

        if (id == null) {
            return true;
        }

        for (int i = 0; i < id.length; i++) {
            if (id[i] != 0x00) {
                return false;
            }
        }

        return true;
    }

    /**
     * Add the session for possible resumption
     * @param session the session to add to stored session map
     * @return SSL_SUCCESS on success
     */
    protected int addSession(WolfSSLImplementSSLSession session) {

        String toHash;
        int    hashCode = 0;

        /* Don't store session if invalid (or not complete with sesPtr
         * if on client side). Server-side still needs to store session
         * for things like returning the session ID, even though sesPtr
         * will be 0 since server manages session cache at native level. */
        if (!session.isValid() ||
            (session.getSide() == WolfSSL.WOLFSSL_CLIENT_END &&
             !session.sessionPointerSet())) {
            return WolfSSL.SSL_FAILURE;
        }

        /* Lock access to store while adding new session, store is global */
        synchronized (storeLock) {
            if (session.getPeerHost() != null) {
                /* Generate key for storing into session table (host:port) */
                toHash = session.getPeerHost().concat(Integer.toString(
                         session.getPeerPort()));
                hashCode = toHash.hashCode();
            }
            else {
                /* If no peer host is available then create hash key from
                 * session ID if not null, not zero length, and not all zeros */
                byte[] sessionId = session.getId();
                if (sessionId != null && sessionId.length > 0 &&
                    (idAllZeros(sessionId) == false)) {
                    hashCode = Arrays.toString(session.getId()).hashCode();
                }
            }

            /* Always try to store session into cache table, as long as we
             * have a hashCode. If session already exists for hashCode, it
             * will be overwritten with new/refreshed version */
            if (hashCode != 0) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "stored session in cache table (host: " +
                        session.getPeerHost() + ", port: " +
                        session.getPeerPort() + ") " +
                        "hashCode = " + hashCode + " side = " +
                        session.getSideString());
                store.put(hashCode, session);
                session.isInTable = true;
            }
        }

        return WolfSSL.SSL_SUCCESS;
    }


    /**
     * @returns enumerated session IDs
     */
    protected Enumeration<byte[]> getAllIDs() {
        List<byte[]> ret = new ArrayList<byte[]>();

        for (Object obj : store.values()) {
            WolfSSLImplementSSLSession current = (WolfSSLImplementSSLSession)obj;
            ret.add(current.getId());
        }
        return Collections.enumeration(ret);
    }


    /**
     * Getter function for session with session id 'ID'
     * @param ID the session id to search for
     * @param side if the session is expected on the server or client side
     * @return session from the store that has session id 'ID'
     */
    protected WolfSSLImplementSSLSession getSession(byte[] ID) {
        WolfSSLImplementSSLSession ret = null;

        synchronized (storeLock) {
            for (Object obj : store.values()) {
                WolfSSLImplementSSLSession current =
                    (WolfSSLImplementSSLSession)obj;
                if (java.util.Arrays.equals(ID, current.getId())) {
                    ret = current;
                    break;
                }
            }

            return ret;
        }
    }

    /**
     * Goes through the list of sessions and checks for timeouts. If timed out
     * then the session is invalidated.
     * @params in the updated timeout value to check against
     */
    protected void updateTimeouts(int in) {
        Date currentDate = new Date();
        long now = currentDate.getTime();

        for (Object obj : store.values()) {
            long diff;
            WolfSSLImplementSSLSession current =
                (WolfSSLImplementSSLSession)obj;

            /* difference in seconds */
            diff = (now - current.creation.getTime()) / 1000;

            if (diff < 0) {
                /* session is from the future ... */ //@TODO

            }

            if (in > 0 && diff > in) {
                current.invalidate();
            }
            current.setNativeTimeout(in);
        }
    }


    private class SessionStore<K, V> extends LinkedHashMap<K, V> {
        /**
         * user defined ID
         */
        private static final long serialVersionUID = 1L;
        private final int maxSz;

        /**
         * @param in max size of hash map before oldest entry is overwritten
         */
        protected SessionStore(int in) {
            maxSz = in;
        }

        @Override
        protected boolean removeEldestEntry(Map.Entry<K, V> oldest) {
            return size() > maxSz;
        }
    }
}

