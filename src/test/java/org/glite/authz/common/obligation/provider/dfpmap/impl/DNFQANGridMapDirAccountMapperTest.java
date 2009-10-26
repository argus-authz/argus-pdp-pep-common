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

package org.glite.authz.common.obligation.provider.dfpmap.impl;

import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

import javax.security.auth.x500.X500Principal;

import junit.framework.TestCase;

import org.glite.authz.common.obligation.ObligationProcessingException;
import org.glite.authz.common.obligation.provider.dfpmap.AccountMapper;
import org.glite.authz.common.obligation.provider.dfpmap.DFPMFileParser;
import org.glite.authz.common.obligation.provider.dfpmap.FQAN;
import org.glite.authz.common.obligation.provider.dfpmap.PosixAccount;

/**
 * A test of the {@link AccountMapper} when employing the {@link DNPrimaryFQANAccountIndicatorMappingStrategy} and
 * {@link FQANGroupNameMappingStrategy} mapping strategies and {@link MemoryBackedPoolAcountManager} pool account
 * management.
 * 
 * This test is used to test the mapping process but does NOT test appropriate use and populate of a grid map directory.
 */
public class DNFQANGridMapDirAccountMapperTest extends TestCase {

    File gridMapDir;

    private AccountMapper accountMapper;

    private X500Principal dn1, dn2, dn3;

    private FQAN smscg, switch0, switch1, switch2;

    /** {@inheritDoc} */
    protected void setUp() throws Exception {
        super.setUp();

        gridMapDir = new File(System.getProperty("java.io.tmpdir") + File.separator + "gridmapdir");
        gridMapDir.mkdirs();

        ArrayList<String> poolAccountNames = new ArrayList<String>();
        for (String group : Arrays.asList("a", "b", "c")) {
            for (int i = 0; i < 10; i++) {
                poolAccountNames.add("test" + group + i);
            }
        }

        int count = 3;
        File poolAccountFile;
        HashMap<String, Long> uidMappings = new HashMap<String, Long>();
        for (String name : poolAccountNames) {
            poolAccountFile = new File(gridMapDir, name);
            poolAccountFile.createNewFile();
            uidMappings.put(name, new Long(count));
            count++;
        }
        uidMappings.put("glite", new Long(1));
        uidMappings.put("user1", new Long(2));
        MemoryBackedIDMappingStrategy uidMappingStrategy = new MemoryBackedIDMappingStrategy(uidMappings);

        HashMap<String, Long> gidMappings = new HashMap<String, Long>();
        gidMappings.put("glite", new Long(1));
        gidMappings.put("user1", new Long(2));
        gidMappings.put("testa", new Long(3));
        gidMappings.put("testb", new Long(4));
        gidMappings.put("testc", new Long(5));
        MemoryBackedIDMappingStrategy gidMappingStrategy = new MemoryBackedIDMappingStrategy(gidMappings);

        DFPMFileParser fileParser = new DFPMFileParser();

        OrderedDFPM accountMap = new OrderedDFPM();
        File accountMapFile = new File(this.getClass().getResource("/00accountMap.txt").toURI());
        fileParser.parse(accountMap, new FileReader(accountMapFile));

        OrderedDFPM groupMap = new OrderedDFPM();
        File groupMapFile = new File(this.getClass().getResource("/00groupMap.txt").toURI());
        fileParser.parse(groupMap, new FileReader(groupMapFile));

        DFPMMatchStrategy<X500Principal> dnMatchStrategy = new X509MatchStrategy();
        DFPMMatchStrategy<FQAN> fqanMatchStrategy = new FQANMatchStrategy();

        DNPrimaryFQANAccountIndicatorMappingStrategy aimStrategy = new DNPrimaryFQANAccountIndicatorMappingStrategy(
                accountMap, dnMatchStrategy, fqanMatchStrategy, false);
        FQANGroupNameMappingStrategy gnmStrategy = new FQANGroupNameMappingStrategy(groupMap, fqanMatchStrategy);
        GridMapDirPoolAccountManager pam = new GridMapDirPoolAccountManager(gridMapDir);

        accountMapper = new AccountMapper(aimStrategy, gnmStrategy, pam, uidMappingStrategy, gidMappingStrategy);

        dn1 = new X500Principal("cn=usera, dc=example, dc=org");
        dn2 = new X500Principal("cn=userb, dc=example, dc=org");
        dn3 = new X500Principal("cn=userc, dc=example, dc=org");

        smscg = FQAN.parseFQAN("/smscg");
        switch0 = FQAN.parseFQAN("/switch");
        switch1 = FQAN.parseFQAN("/switch/group1");
        switch2 = FQAN.parseFQAN("/switch/group1/subgroup1");
    }

    /** {@inheritDoc} */
    protected void tearDown() throws Exception {
        super.tearDown();

        for (File file : gridMapDir.listFiles()) {
            file.delete();
        }
        gridMapDir.delete();
    }

    public void testWithoutSecondaryFQANs() throws Exception {
        PosixAccount account;

        account = accountMapper.mapToAccount(dn1, switch0, null);
        assertNotNull(account);
        assertEquals("testa0", account.getLoginName());
        assertEquals(3, account.getUid());
        assertEquals("testa", account.getPrimaryGroup().getName());
        assertEquals(3, account.getPrimaryGroup().getGID());
        assertEquals(0, account.getSecondaryGroups().size());

        account = accountMapper.mapToAccount(dn2, switch0, null);
        assertNotNull(account);
        assertEquals("testa1", account.getLoginName());
        assertEquals(4, account.getUid());
        assertEquals("testa", account.getPrimaryGroup().getName());
        assertEquals(3, account.getPrimaryGroup().getGID());
        assertEquals(0, account.getSecondaryGroups().size());

        account = accountMapper.mapToAccount(dn1, smscg, null);
        assertNotNull(account);
        assertEquals("testc0", account.getLoginName());
        assertEquals(23, account.getUid());
        assertEquals("testc", account.getPrimaryGroup().getName());
        assertEquals(5, account.getPrimaryGroup().getGID());
        assertEquals(0, account.getSecondaryGroups().size());

        try {
            account = accountMapper.mapToAccount(dn1, FQAN.parseFQAN("/xxx"), null);
            fail("Invalid mapping succeeded");
        } catch (ObligationProcessingException e) {
            // this is supposed to happen
        }
    }

    public void testWithSecondaryFQANs() throws Exception {
        PosixAccount account;

        account = accountMapper.mapToAccount(dn1, switch0, Arrays.asList(switch1));
        assertNotNull(account);
        assertEquals("testa0", account.getLoginName());
        assertEquals(3, account.getUid());
        assertEquals("testa", account.getPrimaryGroup().getName());
        assertEquals(3, account.getPrimaryGroup().getGID());
        assertEquals(1, account.getSecondaryGroups().size());
        assertEquals("testb", account.getSecondaryGroups().get(0).getName());
        assertEquals(4, account.getSecondaryGroups().get(0).getGID());

        account = accountMapper.mapToAccount(dn1, switch0, Arrays.asList(switch1, switch2));
        assertNotNull(account);
        assertEquals("testa1", account.getLoginName());
        assertEquals(4, account.getUid());
        assertEquals("testa", account.getPrimaryGroup().getName());
        assertEquals(3, account.getPrimaryGroup().getGID());
        assertEquals(2, account.getSecondaryGroups().size());
        assertEquals("testb", account.getSecondaryGroups().get(0).getName());
        assertEquals(4, account.getSecondaryGroups().get(0).getGID());
        assertEquals("testc", account.getSecondaryGroups().get(1).getName());
        assertEquals(5, account.getSecondaryGroups().get(1).getGID());

        account = accountMapper.mapToAccount(dn1, switch2, Arrays.asList(switch0, switch1));
        assertNotNull(account);
        assertEquals("testc0", account.getLoginName());
        assertEquals(23, account.getUid());
        assertEquals("testc", account.getPrimaryGroup().getName());
        assertEquals(5, account.getPrimaryGroup().getGID());
        assertEquals(2, account.getSecondaryGroups().size());
        assertEquals("testa", account.getSecondaryGroups().get(0).getName());
        assertEquals(3, account.getSecondaryGroups().get(0).getGID());
        assertEquals("testb", account.getSecondaryGroups().get(1).getName());
        assertEquals(4, account.getSecondaryGroups().get(1).getGID());

        account = accountMapper.mapToAccount(dn1, switch2, Arrays.asList(switch0, FQAN.parseFQAN("/group99"), switch1));
        assertNotNull(account);
        assertEquals("testc0", account.getLoginName());
        assertEquals(23, account.getUid());
        assertEquals("testc", account.getPrimaryGroup().getName());
        assertEquals(5, account.getPrimaryGroup().getGID());
        assertEquals(2, account.getSecondaryGroups().size());
        assertEquals("testa", account.getSecondaryGroups().get(0).getName());
        assertEquals(3, account.getSecondaryGroups().get(0).getGID());
        assertEquals("testb", account.getSecondaryGroups().get(1).getName());
        assertEquals(4, account.getSecondaryGroups().get(1).getGID());

        account = accountMapper.mapToAccount(dn1, switch2, Arrays.asList(FQAN.parseFQAN("/group99"), switch1, switch0));
        assertNotNull(account);
        assertEquals("testc0", account.getLoginName());
        assertEquals(23, account.getUid());
        assertEquals("testc", account.getPrimaryGroup().getName());
        assertEquals(5, account.getPrimaryGroup().getGID());
        assertEquals(2, account.getSecondaryGroups().size());
        assertEquals("testa", account.getSecondaryGroups().get(0).getName());
        assertEquals(3, account.getSecondaryGroups().get(0).getGID());
        assertEquals("testb", account.getSecondaryGroups().get(1).getName());
        assertEquals(4, account.getSecondaryGroups().get(1).getGID());

        account = accountMapper.mapToAccount(dn1, FQAN.parseFQAN(switch0.toString() + "/Role=production"), Arrays
                .asList(switch1, switch2));
        assertNotNull(account);
        assertEquals("testb0", account.getLoginName());
        assertEquals(13, account.getUid());
        assertEquals("testb", account.getPrimaryGroup().getName());
        assertEquals(4, account.getPrimaryGroup().getGID());
        assertEquals(1, account.getSecondaryGroups().size());
        assertEquals("testc", account.getSecondaryGroups().get(0).getName());
        assertEquals(5, account.getSecondaryGroups().get(0).getGID());

        account = accountMapper.mapToAccount(dn1, FQAN.parseFQAN(switch1.toString() + "/Role=production"), Arrays
                .asList(switch0, switch2));
        assertNotNull(account);
        assertEquals("user1", account.getLoginName());
        assertEquals(2, account.getUid());
        assertEquals("user1", account.getPrimaryGroup().getName());
        assertEquals(2, account.getPrimaryGroup().getGID());
        assertEquals(2, account.getSecondaryGroups().size());
        assertEquals("testa", account.getSecondaryGroups().get(0).getName());
        assertEquals(3, account.getSecondaryGroups().get(0).getGID());
        assertEquals("testc", account.getSecondaryGroups().get(1).getName());
        assertEquals(5, account.getSecondaryGroups().get(1).getGID());

        account = accountMapper.mapToAccount(dn1, switch2, Arrays.asList(FQAN.parseFQAN(switch1.toString()
                + "/Role=pilot"), switch0));
        assertNotNull(account);
        assertEquals("testc1", account.getLoginName());
        assertEquals(24, account.getUid());
        assertEquals("testc", account.getPrimaryGroup().getName());
        assertEquals(5, account.getPrimaryGroup().getGID());
        assertEquals(2, account.getSecondaryGroups().size());
        assertEquals("testa", account.getSecondaryGroups().get(0).getName());
        assertEquals(3, account.getSecondaryGroups().get(0).getGID());
        assertEquals("glite", account.getSecondaryGroups().get(1).getName());
        assertEquals(1, account.getSecondaryGroups().get(1).getGID());

        account = accountMapper.mapToAccount(dn1, FQAN.parseFQAN(switch0.toString() + "/Role=pilot"), Arrays
                .asList(FQAN.parseFQAN(switch1.toString() + "/Role=production")));
        assertNotNull(account);
        assertEquals("glite", account.getLoginName());
        assertEquals(1, account.getUid());
        assertEquals("glite", account.getPrimaryGroup().getName());
        assertEquals(1, account.getPrimaryGroup().getGID());
        assertEquals(1, account.getSecondaryGroups().size());
        assertEquals("user1", account.getSecondaryGroups().get(0).getName());
        assertEquals(2, account.getSecondaryGroups().get(0).getGID());
    }
}