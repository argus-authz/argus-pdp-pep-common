/*
 * Copyright 2009 Members of the EGEE Collaboration.
 * See http://www.eu-egee.org/partners for details on the copyright holders. 
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

package org.glite.authz.common.obligation.provider.dfpmap;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.glite.authz.common.util.Strings;

/** Representation of a POSIX user account. */
public class PosixAccount implements Serializable {

    /** Serial version UID. */
    private static final long serialVersionUID = -6232923043396000457L;

    /** Account login name. */
    private String loginName;

    /** UID for this account. */
    private long uid;

    /** Primary group name for this account. */
    private Group primaryGroup;

    /** Secondary group names for this account. */
    private List<Group> secondaryGroups;

    /** Precomputed string representation of this object. */
    private String stringRepresentation;

    /**
     * Constructor.
     * 
     * @param username user name of the account
     * @param uid uid of the account
     * @param gids GIDs of the account with the primary GID listed first
     */
    public PosixAccount(String login, long uid, Group primaryGroup, List<Group> secondaryGroups) {
        this.loginName = Strings.safeTrimOrNullString(login);
        if (this.loginName == null) {
            throw new IllegalArgumentException("Login name may not be empty or null");
        }

        this.uid = uid;

        this.primaryGroup = primaryGroup;
        if (this.primaryGroup == null) {
            throw new IllegalArgumentException("Primary group may not be empty or null");
        }

        if (secondaryGroups != null && !secondaryGroups.isEmpty()) {
            this.secondaryGroups = Collections.unmodifiableList(new ArrayList<Group>(secondaryGroups));
        } else {
            this.secondaryGroups = Collections.emptyList();
        }

        computeString();
    }

    /**
     * Gets the login name for the account.
     * 
     * @return login name for the account
     */
    public String getLoginName() {
        return loginName;
    }

    /**
     * Gets the UID for this account.
     * 
     * @return UID for this account
     */
    public long getUid() {
        return uid;
    }

    /**
     * Gets the primary group for this account.
     * 
     * @return primary group for this account
     */
    public Group getPrimaryGroup() {
        return primaryGroup;
    }

    /**
     * Gets the secondary groups for this account.
     * 
     * @return secondary groups for this account, never null
     */
    public List<Group> getSecondaryGroups() {
        return secondaryGroups;
    }

    /** {@inheritDoc} */
    public int hashCode() {
        int hash = 13;
        hash = 31 * hash + loginName.hashCode();
        hash = 31 * hash + (int)uid;
        hash = 31 * hash + primaryGroup.hashCode();
        hash = 31 * hash + secondaryGroups.hashCode();
        return hash;
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
            PosixAccount other = (PosixAccount) obj;
            return loginName.equals(other.loginName) && uid == other.uid && primaryGroup.equals(other.primaryGroup)
                    && secondaryGroups.equals(other.secondaryGroups);
        }

        return false;
    }

    /** {@inheritDoc} */
    public String toString() {
        return stringRepresentation;
    }

    /** Computes a string representation of this object. */
    private void computeString() {
        StringBuilder string = new StringBuilder("PosixAccount");
        string.append("{");
        string.append("name:").append(loginName).append(", ");
        string.append("uid:").append(uid).append(", ");
        string.append("primary group:").append(primaryGroup).append(", ");
        string.append("secondary groups:").append(secondaryGroups);
        string.append("}");
        stringRepresentation = string.toString();
    }

    /** Represents a group to which a POSIX account belongs. */
    public static class Group implements Serializable {

        /** Serial version UID. */
        private static final long serialVersionUID = -4191113371456785380L;

        /** Name of the group. */
        private String name;

        /** GID of the group. */
        private long gid;

        /**
         * Constructor.
         * 
         * @param name name of the group
         * @param id GID of the group
         */
        public Group(String name, long id) {
            this.name = Strings.safeTrim(name);
            if (this.name == null) {
                throw new IllegalArgumentException("POSIX Group name may not be null");
            }

            gid = id;
        }

        /**
         * Get the name of the group.
         * 
         * @return name of the group
         */
        public String getName() {
            return name;
        }

        /**
         * Gets the GID of the group.
         * 
         * @return GID for the group
         */
        public long getGID() {
            return gid;
        }

        /** {@inheritDoc} */
        public String toString() {
            return "{" + name + ":" + gid + "}";
        }

        /** {@inheritDoc} */
        public int hashCode() {
            int hash = 13;
            hash = 31 * hash + name.hashCode();
            hash = 31 * hash + (int)gid;
            return hash;
        }

        /** {@inheritDoc} */
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }

            if (obj == null) {
                return false;
            }

            if (obj instanceof Group) {
                Group other = (Group) obj;
                return name.equals(other.name) && gid == other.gid;
            }

            return false;
        }
    }
}