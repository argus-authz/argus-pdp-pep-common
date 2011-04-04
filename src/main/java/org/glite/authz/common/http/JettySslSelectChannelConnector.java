/*
 * Copyright (c) Members of the EGEE Collaboration. 2006-2010.
 * See http://www.eu-egee.org/partners/ for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.glite.authz.common.http;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.mortbay.jetty.security.SslSelectChannelConnector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Any extension to the basic Jetty SSL connection handler that allows a
 * pre-instantiated key and trust manager to be used when create new SSL
 * connections.
 */
public class JettySslSelectChannelConnector extends SslSelectChannelConnector {

    private Logger log= LoggerFactory.getLogger(JettySslSelectChannelConnector.class);

    /** {@link KeyManager} used by this TLS connector. */
    private X509KeyManager keyManager;

    /** {@link TrustManager} used by this TLS connector. */
    private X509TrustManager trustManager;

    /**
     * Constructor.
     * 
     * @param key
     *            the key manager used for the TLS connections
     * @param trust
     *            the trust manager used for the TLS connections
     */
    public JettySslSelectChannelConnector(X509KeyManager key,
            X509TrustManager trust) {
        super();

        if (key == null) {
            throw new IllegalArgumentException("X.509 key manager may not be null");
        }
        keyManager= key;

        if (trust == null) {
            throw new IllegalArgumentException("X.509 trust manager may not be null");
        }
        trustManager= trust;        
    }

    /**
     * Disable the all ECDH cipher suites because of the OpenSSL 1.0 problem
     * with SSL handshake.
     * <p>
     * {@inheritDoc}
     */
    protected SSLEngine createSSLEngine() throws IOException {
        SSLEngine sslEngine= super.createSSLEngine();
        String enabledCipherSuites[]= sslEngine.getEnabledCipherSuites();
        List<String> cipherSuites= new ArrayList<String>(Arrays.asList(enabledCipherSuites));
        for (String cipher : enabledCipherSuites) {
            if (cipher.contains("ECDH")) {
                log.debug("disabling cipher: {}", cipher);
                cipherSuites.remove(cipher);
            }
        }
        log.debug("enabling ciphers: {}", cipherSuites);
        enabledCipherSuites= (String[]) cipherSuites.toArray(new String[cipherSuites.size()]);
        sslEngine.setEnabledCipherSuites(enabledCipherSuites);
        return sslEngine;
    }

    /** {@inheritDoc} */
    protected SSLContext createSSLContext() throws Exception {
        SSLContext sslConext= SSLContext.getInstance("TLS");
        sslConext.init(new KeyManager[] { keyManager },
                       new TrustManager[] { trustManager },
                       null);
        return sslConext;
    }

}