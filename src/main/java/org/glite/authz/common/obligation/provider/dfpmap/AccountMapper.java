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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.glite.authz.common.obligation.ObligationProcessingException;
import org.glite.authz.common.obligation.provider.dfpmap.impl.PosixUtil;
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
        if (primaryFQAN == null) {
            return mapToAccountByDN(subjectDN);
        } else {
            return mapToAccountByDNFQAN(subjectDN, primaryFQAN, secondaryFQANs);
        }
    }

    /**
     * Maps a subject, identified solely by a DN, to an account.
     * 
     * @param subjectDN DN of the subject
     * 
     * @return account to which the subject is mapped
     * 
     * @throws ObligationProcessingException thrown if there is a problem mapping the user to an account
     */
    private PosixAccount mapToAccountByDN(X500Principal subjectDN) throws ObligationProcessingException {
        log.debug("Attempting to map subject {} to a POSIX account", subjectDN.getName());
        String accountIndicator = accountIndicatorMappingStrategy.mapToAccountIndicator(subjectDN, null, null);
        if (accountIndicator == null) {
            log.error("Unable to map subject" + subjectDN.getName() + " to a POSIX account indicator.");
            throw new ObligationProcessingException("Unable to map subject to a POSIX account");
        }

        boolean indicatorIsPoolAccountPrefix = false;
        if (poolAccountManager.isPoolAccountPrefix(accountIndicator)) {
            indicatorIsPoolAccountPrefix = true;
            accountIndicator = poolAccountManager.getPoolAccountPrefix(accountIndicator);
        }

        String loginName;
        if (indicatorIsPoolAccountPrefix) {
            loginName = poolAccountManager.mapToAccount(accountIndicator, subjectDN, null, null);
        } else {
            loginName = accountIndicator;
        }
        if (loginName == null) {
            log.error("Subject " + subjectDN.getName() + " could not be mapped to a POSIX login name");
            throw new ObligationProcessingException("Unable to map subject to a POSIX account");
        }
        
        // We have to resolve the primary group information from /etc/passwd here
        // since no FQANs are available, secondary groups are not set in this case
        Passwd accountInfo = PosixUtil.getAccountByName(loginName);
        if (accountInfo == null) {
            log.error("POSIX account with login name " + loginName
                    + " is not configured, unable to determine primary group");
            throw new ObligationProcessingException("Unable to determine primary group");
        }
        
        String primaryGroupName = gidMappingStrategy.mapToName((int)accountInfo.getGID());
        if (primaryGroupName == null) {
            log.error("POSIX group with GID " + accountInfo.getGID()
                    + " is not configured, unable to determine primary group");
            throw new ObligationProcessingException("Unable to determine primary group");
        }
        
        return buildPosixAccount(loginName, primaryGroupName, null);
    }

    /**
     * Maps a subject, identified by a DN and set of FQANs, to an account.
     * 
     * @param subjectDN DN of the subject
     * @param primaryFQAN subject's primary FQAN
     * @param secondaryFQANs subject's secondary FQAN
     * 
     * @return account to which the subject is mapped
     * 
     * @throws ObligationProcessingException thrown if there is a problem mapping the user to an account
     */
    private PosixAccount mapToAccountByDNFQAN(X500Principal subjectDN, FQAN primaryFQAN, List<FQAN> secondaryFQANs)
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

        String primaryGroupName = null;
        List<String> secondaryGroupNames = null;
        List<String> groupNames = groupNameMappingStrategy.mapToGroupNames(subjectDN, primaryFQAN, secondaryFQANs);
        if (groupNames != null && !groupNames.isEmpty()) {
            primaryGroupName = groupNames.get(0);
            if (groupNames.size() > 1) {
                secondaryGroupNames = groupNames.subList(1, groupNames.size());
            } else {
                secondaryGroupNames = Collections.emptyList();
            }
        }
        if (primaryGroupName == null) {
            log.error("Subject " + subjectDN.getName() + " could not be mapped to a primary group");
            throw new ObligationProcessingException("Subject " + subjectDN.getName()
                    + " could not be mapped to a primary group");
        }

        String loginName;
        if (indicatorIsPoolAccountPrefix) {
            loginName = poolAccountManager.mapToAccount(accountIndicator, subjectDN, primaryGroupName,
                    secondaryGroupNames);
        } else {
            loginName = accountIndicator;
        }
        if (loginName == null) {
            log.error("Subject " + subjectDN.getName() + " could not be mapped to a POSIX login name");
            throw new ObligationProcessingException("Unable to map subject to a POSIX account");
        }
        return buildPosixAccount(loginName, primaryGroupName, secondaryGroupNames);
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
        log.debug("Building POSIX account for login name {} with primary group {} and secondary groups {}",
                new Object[] { loginName, primaryGroupName, secondaryGroupNames });

        Integer uid = uidMappingStrategy.mapToID(loginName);
        if (uid == null) {
            log.error("Unable to resolve login " + loginName
                    + " to a UID.  This login name is not configured on this system");
            throw new ObligationProcessingException("Unable to resolve ID information for mapped account");
        }
        log.debug("Login name {} resolved to UID {}", loginName, uid);

        Integer gid = gidMappingStrategy.mapToID(primaryGroupName);
        if (gid == null) {
            log.error("Unable to resolve group name " + primaryGroupName
                    + " to a GID.  This group name is not configured on this system");
            throw new ObligationProcessingException("Unable to resolve ID information for mapped account");
        }
        log.debug("Primary group name {} resolved to GID {}", primaryGroupName, gid);
        PosixAccount.Group primaryGroup = new PosixAccount.Group(primaryGroupName, gid);

        ArrayList<PosixAccount.Group> secondaryGroups = null;
        if (secondaryGroupNames != null && !secondaryGroupNames.isEmpty()) {
            secondaryGroups = new ArrayList<PosixAccount.Group>();
            for (String name : secondaryGroupNames) {
                gid = gidMappingStrategy.mapToID(name);
                if (gid == null) {
                    log.error("Unable to resolve group name " + name
                            + " to a GID.  This group name is not configured on this system");
                    throw new ObligationProcessingException("Unable to resolve ID information for mapped account");
                }
                log.debug("Secondary group name {} resolved to GID {}", name, gid);
                secondaryGroups.add(new PosixAccount.Group(name, gid));
            }
        }

        return new PosixAccount(loginName, uid, primaryGroup, secondaryGroups);
    }
}