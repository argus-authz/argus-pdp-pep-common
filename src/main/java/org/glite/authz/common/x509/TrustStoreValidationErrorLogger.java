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
package org.glite.authz.common.x509;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.emi.security.authn.x509.ValidationError;
import eu.emi.security.authn.x509.ValidationErrorListener;

/**
 * A {@link ValidationErrorListener} to log X.509 validation errors.
 * 
 * @since 1.4
 */
public class TrustStoreValidationErrorLogger implements ValidationErrorListener {

    /** Class logger. */
    private final Logger log= LoggerFactory.getLogger(TrustStoreValidationErrorLogger.class);

    /*
     * (non-Javadoc)
     * 
     * @see
     * eu.emi.security.authn.x509.ValidationErrorListener#onValidationError(
     * eu.emi.security.authn.x509.ValidationError)
     */
    public boolean onValidationError(ValidationError error) {
        log.error("Validation error: {}", error);
        return false;
    }

}