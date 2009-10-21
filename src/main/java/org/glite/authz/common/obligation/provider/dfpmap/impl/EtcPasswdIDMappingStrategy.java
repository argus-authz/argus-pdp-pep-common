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

package org.glite.authz.common.obligation.provider.dfpmap.impl;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.LineNumberReader;
import java.util.HashMap;

import org.glite.authz.common.obligation.ObligationProcessingException;
import org.glite.authz.common.obligation.provider.dfpmap.IDMappingStrategy;
import org.glite.authz.common.util.Files;
import org.glite.authz.common.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Resolves a name against an /etc/passwd file and returns its UID. */
public class EtcPasswdIDMappingStrategy implements IDMappingStrategy {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(EtcPasswdIDMappingStrategy.class);

    /** Map from login name to UID. */
    private HashMap<String, Integer> nameToIdMap;

    /** Map from UID to login name. */
    private HashMap<Integer, String> idToNameMap;

    /** Constructor. */
    public EtcPasswdIDMappingStrategy() {
        nameToIdMap = new HashMap<String, Integer>();
        idToNameMap = new HashMap<Integer, String>();
        readEtcPasswd();
    }

    /** {@inheritDoc} */
    public Integer mapToID(String name) throws ObligationProcessingException {
        return nameToIdMap.get(name);
    }

    /** {@inheritDoc} */
    public String mapToName(int id) throws ObligationProcessingException {
        return idToNameMap.get(new Integer(id));
    }

    /** Reads the /etc/passwd file and loads it in to the map. */
    private void readEtcPasswd() {
        File etcPasswdFile = null;
        try {
            etcPasswdFile = Files.getReadableFile("/etc/passwd");
        } catch (IOException e) {
            log.error(e.getMessage());
            return;
        }

        try {
            LineNumberReader etcPasswdReader = new LineNumberReader(new FileReader(etcPasswdFile));
            log.debug("Reading /etc/passwd file");

            String line = etcPasswdReader.readLine();
            String trimmedLine;
            String[] entry;
            Integer uid;
            String loginName;
            while (line != null) {
                trimmedLine = Strings.safeTrimOrNullString(line);
                if (trimmedLine != null && !trimmedLine.startsWith("#")) {
                    entry = trimmedLine.split(":");
                    log.trace("/etc/passwd line {} maps login name {} to GID {}", new Object[] {
                            etcPasswdReader.getLineNumber(), entry[0], entry[2] });
                    try {
                        uid = new Integer(entry[2]);
                        loginName = Strings.safeTrimOrNullString(entry[0]);
                        nameToIdMap.put(loginName, uid);
                        idToNameMap.put(uid, loginName);
                    } catch (NumberFormatException e) {
                        log.warn("The UID {} is not a valid, the /etc/passwd entry on line {} is being ignored",
                                entry[2], etcPasswdReader.getLineNumber());
                    }
                } else {
                    log.trace("Ignoring /etc/passwd line {} because it empty or a comment", etcPasswdReader
                            .getLineNumber());
                }
                line = etcPasswdReader.readLine();
            }
        } catch (IOException e) {
            log.error("Error while reading /etc/passwd file", e);
        }
    }
}