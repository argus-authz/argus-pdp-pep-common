/*
 * Copyright 2009 EGEE Collaboration
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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.glite.authz.common.obligation.ObligationProcessingException;
import org.glite.authz.common.obligation.provider.dfpmap.impl.PosixUtil;
import org.jruby.ext.posix.Group;
import org.jruby.ext.posix.Passwd;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Maps a subject to a POSIX account based on the subject's DN, primary FQAN, and secondary FQANs. */
public class AccountMapper {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(AccountMapper.class);

    /** Strategy used to map a subject to a pool account indicator. */
    private final AccountIndicatorMappingStrategy accountIndicatorMappingStrategy;

    /** Strategy used to map a subject to a set of group names. */
    private final GroupNameMappingStrategy groupNameMappingStrategy;

    /** Manager used to track and access pool accounts. */
    private final PoolAccountManager poolAccountManager;

    /** Strategy used to map a POSIX login name to a UID. */
    private final IDMappingStrategy uidMappingStrategy;

    /** Strategy used to map a POSIX group name to a GID. */
    private final IDMappingStrategy gidMappingStrategy;

    /**
     * Constructor.
     * 
     * @param aimStrategy strategy used to map a subject to a pool account indicator
     * @param gnmStrategy strategy used to map a subject to a set of group names
     * @param pam manager used to track and access pool accounts
     */
    public AccountMapper(AccountIndicatorMappingStrategy aimStrategy, GroupNameMappingStrategy gnmStrategy,
            PoolAccountManager pam, IDMappingStrategy uidStategy, IDMappingStrategy gidStrategy) {
        if (aimStrategy == null) {
            throw new IllegalArgumentException("Account indiciator mapping strategy may not be null");
        }
        accountIndicatorMappingStrategy = aimStrategy;

        if (gnmStrategy == null) {
            throw new IllegalArgumentException("Group name mapping strategy may not be null");
        }
        groupNameMappingStrategy = gnmStrategy;

        if (pam == null) {
            throw new IllegalArgumentException("Pool account manager may not be null");
        }
        poolAccountManager = pam;

        if (uidStategy == null) {
            throw new IllegalArgumentException("UID mapping strategy may not be null");
        }
        uidMappingStrategy = uidStategy;

        if (gidStrategy == null) {
            throw new IllegalArgumentException("GID mapping strategy may not null");
        }
        gidMappingStrategy = gidStrategy;
    }

    /**
     * Maps a subject to a POSIX account.
     * 
     * @param subjectDN subject's DN
     * @param primaryFQAN subject's primary FQAN, may be null
     * @param secondaryFQANs subject's secondary FQANs, may be null
     * 
     * @return account to which the subject is mapped
     * 
     * @throws ObligationProcessingException thrown is there is a problem mapping the subject to an account
     */
    public PosixAccount mapToAccount(X500Principal subjectDN, FQAN primaryFQAN, List<FQAN> secondaryFQANs)
            throws ObligationProcessingException {
        log.debug("Attempting to map subject {} with primary FQAN {} and secondary FQANs {} to a POSIX account",
                new Object[] { subjectDN.getName(), primaryFQAN, secondaryFQANs });
        String accountIndicator = accountIndicatorMappingStrategy.mapToAccountIndicator(subjectDN, primaryFQAN,
                secondaryFQANs);
        if (accountIndicator == null) {
            log.error("Unable to map subject" + subjectDN.getName() + " with primary FQAN " + primaryFQAN
                    + " and secondary FQANs " + secondaryFQANs + " to a POSIX account indicator.");
            throw new ObligationProcessingException("Unable to map subject to a POSIX account");
        }

        boolean indicatorIsPoolAccountPrefix = false;
        if (poolAccountManager.isPoolAccountPrefix(accountIndicator)) {
            indicatorIsPoolAccountPrefix = true;
            accountIndicator = poolAccountManager.getPoolAccountPrefix(accountIndicator);
        }

        List<String> groupNames = mapToGroupNames(subjectDN, primaryFQAN, secondaryFQANs, accountIndicator,
                indicatorIsPoolAccountPrefix);

        String loginName;
        String primaryGroupName = groupNames.get(0);
        List<String> secondaryGroupNames;
        if (groupNames.size() > 1) {
            secondaryGroupNames = groupNames.subList(1, groupNames.size());
        } else {
            secondaryGroupNames = Collections.emptyList();
        }

        if (indicatorIsPoolAccountPrefix) {
            loginName = poolAccountManager.mapToAccount(accountIndicator, subjectDN, primaryGroupName,
                    secondaryGroupNames);
        } else {
            loginName = accountIndicator;
        }

        if (loginName == null) {
            return null;
        }
        return buildPosixAccount(loginName, primaryGroupName, secondaryGroupNames);
    }

    /**
     * Maps the subject to a set of POSIX groups.
     * 
     * @param subjectDN subject's DN
     * @param primaryFQAN subject's primary FQAN, may be null
     * @param secondaryFQANs subject's secondary FQANs, may be null
     * @param accountIndicator the account indicator to which the subject was mapped
     * @param indicatorIsPoolAccountPrefix whether the indicator is a pool account prefix
     * 
     * @return the list of groups, with the primary group first, to which the subject was mapped
     * 
     * @throws ObligationProcessingException thrown if there is a problem mapping the subject to a set of groups
     */
    private List<String> mapToGroupNames(X500Principal subjectDN, FQAN primaryFQAN, List<FQAN> secondaryFQANs,
            String accountIndicator, boolean indicatorIsPoolAccountPrefix) throws ObligationProcessingException {
        
        List<String> groupNames;
        if (primaryFQAN != null) {
            groupNames = groupNameMappingStrategy.mapToGroupNames(subjectDN, primaryFQAN, secondaryFQANs);
        } else {
            groupNames = mapToGroupNames(accountIndicator);
        }

        if(groupNames == null || groupNames.size() < 1){
            log.error("Subject " + subjectDN.getName() + " could not be mapped to a primary group");
            throw new ObligationProcessingException("Subject " + subjectDN.getName() + " could not be mapped to a primary group");
        }
        return groupNames;
    }

    /**
     * Gets the name of the primary group for the given POSIX account.
     * 
     * @param loginName login name for the POSIX account
     * 
     * @return the name of the primary group, or null if the account is null, its primary group does not exist or does
     *         not have a name
     */
    private List<String> mapToGroupNames(String loginName) throws ObligationProcessingException{
        ArrayList<String> names = new ArrayList<String>();
        Passwd accountInfo = PosixUtil.getAccountByName(loginName);
        if (accountInfo == null) {
            log.error("POSIX account with login name " + loginName + " is not configured, unable to determine primary group");
            throw new ObligationProcessingException("Unable to determine primary group");
        }

        Group groupInfo = PosixUtil.getGroupByID((int) accountInfo.getGID());
        if(groupInfo == null){
            log.error("POSIX group with GID " + accountInfo.getGID() + " is not configured, unable to determine primary group");
            throw new ObligationProcessingException("Unable to determine primary group");
        }
        names.add(groupInfo.getName());
        return names;
    }

    /**
     * Creates a POSIX account from the given information. The registered {@link IDMappingStrategy} objects are used to
     * convert the login name and group names in to their respective IDs.
     * 
     * @param loginName login name of the account
     * @param primaryGroupName name of the primary group
     * @param secondaryGroupNames names of the secondary groups
     * 
     * @return the POSIX account
     * 
     * @throws ObligationProcessingException thrown if a name can not be resolved to an ID
     */
    private PosixAccount buildPosixAccount(String loginName, String primaryGroupName, List<String> secondaryGroupNames)
            throws ObligationProcessingException {
        int uid = uidMappingStrategy.mapToID(loginName);

        PosixAccount.Group primaryGroup = new PosixAccount.Group(primaryGroupName, gidMappingStrategy
                .mapToID(primaryGroupName));

        ArrayList<PosixAccount.Group> secondaryGroups = null;
        if (secondaryGroupNames != null && !secondaryGroupNames.isEmpty()) {
            secondaryGroups = new ArrayList<PosixAccount.Group>();
            for (String name : secondaryGroupNames) {
                secondaryGroups.add(new PosixAccount.Group(name, gidMappingStrategy.mapToID(name)));
            }
        }

        return new PosixAccount(loginName, uid, primaryGroup, secondaryGroups);
    }
}