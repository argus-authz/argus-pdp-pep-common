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

import eu.emi.security.authn.x509.X509CertChainValidatorExt;

/**
 * A task that dispose a {@link X509CertChainValidatorExt}. This task is
 * intended to be used as a shutdown task within a {@link JettyAdminService}.
 */
public class CertChainValidatorDisposeTask implements ShutdownTask {

    /** X.509 cert chain validator to be dispose. */
    private X509CertChainValidatorExt certChainValidator;

    /**
     * Constructor.
     * 
     * @param timer
     *            timer to be shutdown.
     */
    public CertChainValidatorDisposeTask(X509CertChainValidatorExt validator) {
        certChainValidator= validator;
    }

    /** {@inheritDoc} */
    public void run() {
        if (certChainValidator != null) {
            certChainValidator.dispose();
        }
    }
}