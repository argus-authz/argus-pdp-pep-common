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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.obligation.provider.gridmap.AccountMapper;
import org.glite.authz.common.obligation.provider.gridmap.FQAN;
import org.glite.authz.common.obligation.provider.gridmap.GridMap;
import org.glite.authz.common.obligation.provider.gridmap.GridMapKey;
import org.jruby.ext.posix.Group;
import org.jruby.ext.posix.Passwd;
import org.opensaml.util.storage.StorageService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 */
@ThreadSafe
public class PosixAccountMapper implements AccountMapper<PosixAccount> {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(PosixAccountMapper.class);

    /** The grid map used to map DN's and FQANs to a POSIX UIDs. */
    private GridMap uidGridMap;

    /** The grid map used to map DN's and FQANs to a set of POSIX GIDs. */
    private GridMap gidGridMap;

    /** Service used to store account mappings. */
    private StorageService<String, PosixAccount> storageService;

    /** Length of time, in milliseconds, an account mapping is kept. */
    private long accountMappingLifetime;

    public PosixAccountMapper(GridMap uidMap, GridMap gidMap, StorageService<String, PosixAccount> mappingStore) {
        uidGridMap = uidMap;
        gidGridMap = gidMap;
        storageService = mappingStore;
    }

    public PosixAccountMapper(GridMap uidMap, GridMap gidMap, StorageService<String, PosixAccount> mappingStore,
            long mappingLifetime) {
        this(uidMap, gidMap, mappingStore);
        accountMappingLifetime = mappingLifetime;
    }

    /** {@inheritDoc} */
    public PosixAccount mapToAccount(String subjectid, List<? extends GridMapKey> keys) {
        if (keys == null || keys.isEmpty()) {
            return null;
        }

        // First key determines the account to which we map
        GridMapKey uidMapKey = keys.get(0);
        log.debug("Using key {} to determine UID for subject {}", uidMapKey.toString(), subjectid);
        Passwd account = selectAccount(uidGridMap.map(uidMapKey, false));

        List<Long> gids = null;
        if (keys.size() > 1) {
            // remaining keys determine GIDs
            gids = mapToGIDs(keys.subList(1, keys.size()));
        }

        PosixAccount posixAccount = new PosixAccount(account.getLoginName(), account.getUID(), gids);
        log.debug("Subject {} has been mapped to {}", subjectid,posixAccount);
        return posixAccount;
    }

    /**
     * Selects an account to which a subject is mapped. The account selected is the first account in the provided list
     * that exists and is not already in use.  In the event that a candidate account name starts with a period ('.') it 
     * will be treated as a "pool" account.  Such account names will be expanded in a set of 999 account names where the 
     * poolname is appended with 001 - 999.
     * 
     * @param possibleAccounts the list of possible account
     * 
     * @return the account selected
     */
    private Passwd selectAccount(List<String> possibleAccounts) {
        if (possibleAccounts == null) {
            return null;
        }

        Passwd account = null;
        String basePoolAccountName;
        String poolAccountName;
        for (String possibleAccount : possibleAccounts) {
            if (possibleAccount.startsWith(".")) {
                basePoolAccountName = possibleAccount.substring(1);
                for (int i = 1; i < 999; i++) {
                    poolAccountName = basePoolAccountName + to3DigitString(i);
                    if (!isAccountInUse(poolAccountName)) {
                        account = PosixUtil.getAccountByName(poolAccountName);
                        if (account != null) {
                            return account;
                        }
                    }
                }
            } else {
                account = PosixUtil.getAccountByName(possibleAccount);
                if (account != null) {
                    return account;
                }
            }
        }

        return null;
    }

    private boolean isAccountInUse(String accountName) {
        return false;
    }

    /**
     * Maps a set of {@link FQAN}s to a list of GIDs.
     * 
     * @param keys keys to map to GIDs
     * 
     * @return the set of GIDs for the account with the primary GID being the first in the list
     */
    private List<Long> mapToGIDs(List<? extends GridMapKey> keys) {
        ArrayList<Long> gids = new ArrayList<Long>();

        List<String> groupNames;
        Group group;
        for (GridMapKey key : keys) {
            if (!(key instanceof FQAN)) {
                continue;
            }

            groupNames = gidGridMap.map(key, true);
            if (groupNames == null || groupNames.isEmpty()) {
                continue;
            }
            for (String groupName : groupNames) {
                group = PosixUtil.getGroupByName(groupName);
                if (group != null) {
                    gids.add(new Long(group.getGID()));
                }
            }
        }

        // Remove any nulls or duplicate GID entries from the list
        ArrayList<Long> visitedGIDs = new ArrayList<Long>();
        Iterator<Long> gidIter = gids.iterator();
        Long gid;
        while (gidIter.hasNext()) {
            gid = gidIter.next();
            if (gid == null || visitedGIDs.contains(gid)) {
                gidIter.remove();
            }
            visitedGIDs.add(gid);
        }

        return gids;
    }

    /**
     * Converts an integer to a 3-digit string. If the integer is less than 100 it is left padded with 0s in order to
     * make it 3-digits.
     * 
     * @param integer the integer to convert, must be in the range 0 - 999
     * 
     * @return the 3-digit string for the integer
     */
    private String to3DigitString(int integer) {
        if (integer < 0 || integer > 999) {
            throw new IllegalArgumentException("Integer must be in the range 0 - 999");
        }

        if (integer < 10) {
            return new String("00" + integer);
        }

        if (integer < 100) {
            return new String("0" + integer);
        }

        return Integer.toString(integer);
    }
}