/*
 * Copyright 2008 EGEE Collaboration
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.glite.authz.common.obligation.provider.gridmap;

import javax.security.auth.x500.X500Principal;

import org.glite.authz.common.obligation.provider.gridmap.GridMap.GridMapKeyMatchFunction;

/** An X.509 distinguished name. */
public class X509DistinguishedName implements GridMapKey {

    /** The DN. */
    private X500Principal dn;

    /**
     * Constructor.
     * 
     * @param name the DN
     */
    public X509DistinguishedName(X500Principal name) {
        if (name == null) {
            throw new NullPointerException("DN may not be null or empty");
        }
        dn = name;
    }

    public String toCanonicalString() {
        return dn.getName(X500Principal.CANONICAL);
    }

    public String toRFC2253String() {
        return dn.getName(X500Principal.RFC2253);
    }

    public String toGridDNString() {
        //TODO 
        return null;
    }

    /** {@inheritDoc} */
    public String toString() {
        return toRFC2253String();
    }

    /** {@inheritDoc} */
    public int hashCode() {
        return dn.hashCode();
    }

    /** {@inheritDoc} */
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }

        if (obj instanceof X509DistinguishedName) {
            return hashCode() == obj.hashCode();
        }

        return false;
    }

    /** A {@link GridMapKeyMatchFunction} for {@link X509DistinguishedName} objects. */
    public static class MatchFunction implements GridMapKeyMatchFunction {

        /** {@inheritDoc} */
        public boolean matches(GridMapKey target, GridMapKey candidate) {
            if (target instanceof X509DistinguishedName && candidate instanceof X509DistinguishedName) {
                return ((X509DistinguishedName) target).toCanonicalString().equals(
                        ((X509DistinguishedName) candidate).toCanonicalString());
            }

            return false;
        }
    }
}