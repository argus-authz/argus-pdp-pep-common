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

import org.glite.authz.common.util.Strings;

/** An X.509 distinguished name. */
public class DN implements FullyQualifiedName {

    /** The DN. */
    private String dn;

    /**
     * Constructor.
     * 
     * @param name the DN
     */
    public DN(String name) {
        dn = Strings.safeTrimOrNullString(name);
        if (dn == null) {
            throw new IllegalArgumentException("DN may not be null or empty");
        }
    }

    /** {@inheritDoc} */
    public String toString() {
        return dn;
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

        if (obj instanceof DN) {
            return hashCode() == obj.hashCode();
        }

        return false;
    }
}