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
import com.wolfssl.WolfSSL.TLS_VERSION;
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

            /* default session cache size of 33 to match native wolfSSL
             * default cache size */
            int defaultCacheSize = 33;

        if (version == TLS_VERSION.INVALID) {
            throw new IllegalArgumentException("Invalid SSL/TLS version");
        }

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "Creating new WolfSSLAuthStore");

        initKeyManager(keyman);
        initTrustManager(trustman);
        initSecureRandom(random);

        this.currentVersion = version;
        store = new SessionStore<>(defaultCacheSize);
        this.serverCtx = new WolfSSLSessionContext(
                this, defaultCacheSize, WolfSSL.WOLFSSL_SERVER_END);
        this.clientCtx = new WolfSSLSessionContext(
                this, defaultCacheSize, WolfSSL.WOLFSSL_CLIENT_END);
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
                    "searching installed providers for X509KeyManager (type: "
                    + KeyManagerFactory.getDefaultAlgorithm() +")");

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
                    km = (X509KeyManager)managers[i];
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "located X509KeyManager instance: " + km);
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
                    tm = (X509TrustManager)managers[i];
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "located X509TrustManager instance: " + tm);
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
     * Get X509KeyManager for this object
     * @return get the key manager used
     */
    protected X509KeyManager getX509KeyManager() {
        return this.km;
    }

    /**
     * Get X509TrustManager for this object
     * @return get the trust manager used
     */
    protected X509TrustManager getX509TrustManager() {
        return this.tm;
    }

    /**
     * Get the SecureRandom for this object
     * @return get secure random
     */
    protected SecureRandom getSecureRandom() {
        return this.sr;
    }

    /**
     * Get protocol version set
     * @return get the current protocol version set
     */
    protected TLS_VERSION getProtocolVersion() {
        return this.currentVersion;
    }

    /**
     * Set certificate alias
     * @param in alias to set for certificate used
     */
    protected void setCertAlias(String in) {
        this.alias = in;
    }

    /**
     * Get certificate alias
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
     * @param side server/client side for cache resize
     */
    protected void resizeCache(int sz, int side) {
            SessionStore<Integer, WolfSSLImplementSSLSession> newStore =
                    new SessionStore<>(sz);

        //@TODO check for side server/client, currently a resize is for all
        synchronized (storeLock) {
            store.putAll(newStore);
            store = newStore;
        }
    }

    /**
     * Get and return either an existing session from the Java session cache
     * table, or create a new session if one does not exist.
     *
     * This method can return null if ether an error occurs getting a session,
     * or a new session could not be created.
     *
     * If called on the server side (clientMode == false), a new
     * WolfSSLImplementSSLSession will be created and returned, since the
     * server-side session cache is managed and maintained interal to native
     * wolfSSL.
     *
     * @param ssl WolfSSLSession (WOLFSSL) for which the returned session
     *            is stored back into (ie: wolfSSL_set_session(ssl, session))
     * @param port port number of peer being connected to
     * @param host host of the peer being connected to
     * @param clientMode if is client side then true, otherwise false
     * @return an existing SSLSession from Java session cache, or a new
     *         object if not in cache, called on server side, or host
     *         is null
     */
    protected synchronized WolfSSLImplementSSLSession getSession(
        WolfSSLSession ssl, int port, String host, boolean clientMode) {

        WolfSSLImplementSSLSession ses = null;
        String toHash = null;

        if (ssl == null) {
            return null;
        }

        /* Return new session if in server mode, or if host is null */
        if (!clientMode || host == null) {
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
                /* Make copy/clone of session object so multiple threads
                 * don't try to use the same cache entry. Cache entry will
                 * be overwritten when new session with same key is stored */
                ses = new WolfSSLImplementSSLSession(ses);
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
    protected synchronized WolfSSLImplementSSLSession getSession(
        WolfSSLSession ssl) {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "creating new session");

        WolfSSLImplementSSLSession ses =
            new WolfSSLImplementSSLSession(ssl, this);

        ses.setValid(true);
        ses.isFromTable = false;
        ses.setPseudoSessionId(Integer.toString(ssl.hashCode()).getBytes());

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
     * Add SSLSession into wolfJSSE Java session cache table, to be used
     * for session resumption.
     *
     * Session is stored into the session table using a hash code as the key.
     * If the peer host is not null, the hash code is based on a concatenation
     * of the peer host and port. If the peer host is null, the hash code
     * is based on the session ID (if ID is not null, and non-zero length).
     * Otherwise, no hash code is generated and the session is not stored into
     * the session cache table.
     *
     * This method synchronizes on the static/global storeLock object, since
     * the session cache is global and shared amongst all threads.
     *
     * @param session SSLSession to be stored in Java session cache
     * @return SSL_SUCCESS on success
     */
    protected int addSession(WolfSSLImplementSSLSession session) {

        String toHash;
        int    hashCode = 0;

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
                        session.getSide());
                store.put(hashCode, session);
            }
        }

        return WolfSSL.SSL_SUCCESS;
    }

    /**
     * Internal function to return a list of all session ID's
     * @param side server or client side to get list of ID's from
     * @return enumerated session IDs
     */
    protected Enumeration<byte[]> getAllIDs(int side) {
        List<byte[]> ret = new ArrayList<>();

        synchronized (storeLock) {
            for (Object obj : store.values()) {
                WolfSSLImplementSSLSession current =
                    (WolfSSLImplementSSLSession)obj;
                if (current.getSide() == side) {
                    ret.add(current.getId());
                }
            }

            return Collections.enumeration(ret);
        }
    }

    /**
     * Getter function for session with session id 'ID'
     * @param ID the session id to search for
     * @param side if the session is expected on the server or client side
     * @return session from the store that has session id 'ID'
     */
    protected WolfSSLImplementSSLSession getSession(byte[] ID, int side) {
        WolfSSLImplementSSLSession ret = null;

        synchronized (storeLock) {
            for (Object obj : store.values()) {
                WolfSSLImplementSSLSession current =
                    (WolfSSLImplementSSLSession)obj;
                if (current.getSide() == side &&
                        java.util.Arrays.equals(ID, current.getId())) {
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
     * @param in the updated timeout value to check against
     * @param side server or client side getting the timeout update
     */
    protected void updateTimeouts(int in, int side) {
        Date currentDate = new Date();
        long now = currentDate.getTime();

        synchronized (storeLock) {
            for (Object obj : store.values()) {
                long diff;
                WolfSSLImplementSSLSession current =
                    (WolfSSLImplementSSLSession)obj;

                if (current.getSide() == side) {
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

    @SuppressWarnings("deprecation")
    @Override
    protected synchronized void finalize() throws Throwable {
        /* Clear LinkedHashMap and set to null to allow
         * for garbage collection */
        store.clear();
        store = null;
        super.finalize();
    }
}

