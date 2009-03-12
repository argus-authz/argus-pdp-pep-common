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

import java.io.Serializable;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import org.glite.authz.common.util.Strings;

/** Representation of a POSIX user account. */
public class PosixAccount implements Principal, Serializable {

    /** Serial version UID. */
    private static final long serialVersionUID = 7986675291837206475L;

    /** Human readable name of the account. */
    private String username;

    /** UID of the account. */
    private String uid;

    /** GIDs for the account with the primary GID listed first. */
    private List<String> gids;

    /**
     * Constructor.
     * 
     * @param username user name of the account
     * @param uid uid of the account
     * @param gids GIDs of the account with the primnary GID listed first
     */
    public PosixAccount(String username, String uid, List<String> gids) {
        this.username = Strings.safeTrimOrNullString(username);
        if (this.username == null) {
            throw new IllegalArgumentException("Username may not be empty");
        }

        this.uid = Strings.safeTrimOrNullString(uid);
        if (this.uid == null) {
            throw new IllegalArgumentException("User UID may not be empty");
        }

        if (gids == null || gids.isEmpty()) {
            throw new IllegalArgumentException("User GIDs may not be empty");
        }
        this.gids = new ArrayList<String>();
        this.gids.addAll(gids);
    }

    /** {@inheritDoc} */
    public String getName() {
        return username;
    }

    /**
     * Gets the UID for the user.
     * 
     * @return UID for the user
     */
    public String getUID() {
        return uid;
    }

    /**
     * Gets the GIDs for the user. The first GID in the list is the primary GID.
     * 
     * @return GIDs for the user
     */
    public List<String> getGIDs() {
        return gids;
    }

    /** {@inheritDoc} */
    public int hashCode() {
        return uid.hashCode();
    }

    /** {@inheritDoc} */
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }

        if (obj == this) {
            return true;
        }

        if (obj instanceof PosixAccount) {
            return uid.equals(((PosixAccount) obj).getUID());
        }

        return false;
    }

    /** {@inheritDoc} */
    public String toString() {
        // TODO Auto-generated method stub
        return super.toString();
    }
}