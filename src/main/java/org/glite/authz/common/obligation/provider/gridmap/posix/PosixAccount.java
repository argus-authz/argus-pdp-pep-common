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

package org.glite.authz.common.obligation.provider.gridmap.posix;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.glite.authz.common.util.Strings;

/** Representation of a POSIX user account. */
public class PosixAccount implements Serializable {

    /** Serial version UID. */
    private static final long serialVersionUID = -4015669522137044854L;

    /** Human readable name of the account. */
    private String username;

    /** UID of the account. */
    private long uid;

    /** GIDs for the account with the primary GID listed first. */
    private List<Long> gids;
    
    /** Precomputed string representation of this object. */
    private String stringRepresentation;

    /**
     * Constructor.
     * 
     * @param username user name of the account
     * @param uid uid of the account
     * @param gids GIDs of the account with the primary GID listed first
     */
    public PosixAccount(String username, long uid, List<Long> gids) {
        this.username = Strings.safeTrimOrNullString(username);
        if (this.username == null) {
            throw new IllegalArgumentException("Username may not be empty");
        }

        this.uid = uid;
        if (gids == null) {
            this.gids = Collections.EMPTY_LIST;
        } else {
            this.gids = Collections.unmodifiableList(new ArrayList<Long>(gids));
        }
        
        computeString();
    }

    /** {@inheritDoc} */
    public String getUsername() {
        return username;
    }

    /**
     * Gets the UID for the user.
     * 
     * @return UID for the user
     */
    public long getUID() {
        return uid;
    }

    /**
     * Gets the GIDs for the user. The first GID in the list is the primary GID.
     * 
     * @return GIDs for the user
     */
    public List<Long> getGIDs() {
        return gids;
    }

    /** {@inheritDoc} */
    public int hashCode() {
        return username.hashCode();
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
            return uid == ((PosixAccount) obj).getUID();
        }

        return false;
    }

    /** {@inheritDoc} */
    public String toString() {
        return stringRepresentation;
    }
    
    /** Precomputes a string representation of this object. */
    private void computeString(){
        StringBuilder string = new StringBuilder("PosixAccount");
        string.append("{");
        string.append("name:").append(username).append(", ");
        string.append("uid:").append(uid).append(", ");
        string.append("gid:").append(gids);
        string.append("}");
        stringRepresentation = string.toString(); 
    }
}