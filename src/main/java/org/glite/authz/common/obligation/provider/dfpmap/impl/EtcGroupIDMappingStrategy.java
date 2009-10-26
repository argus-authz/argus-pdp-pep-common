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
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.glite.authz.common.obligation.ObligationProcessingException;
import org.glite.authz.common.obligation.provider.dfpmap.IDMappingStrategy;
import org.glite.authz.common.util.Files;
import org.glite.authz.common.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Resolves a name against an /etc/group file and returns its GID. */
public class EtcGroupIDMappingStrategy implements IDMappingStrategy {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(EtcPasswdIDMappingStrategy.class);

    /** Map from group name to ID. */
    private Map<String, Long> nameToIdMap;

    /** Map from group ID to group name. */
    private Map<Long, String> idToNameMap;

    /** Constructor. */
    public EtcGroupIDMappingStrategy() {
        nameToIdMap = new HashMap<String, Long>();
        idToNameMap = new HashMap<Long, String>();
        readEtcGroup();
        nameToIdMap = Collections.unmodifiableMap(nameToIdMap);
        idToNameMap = Collections.unmodifiableMap(idToNameMap);
    }

    /** {@inheritDoc} */
    public Long mapToID(String name) throws ObligationProcessingException {
        return nameToIdMap.get(name);
    }

    /** {@inheritDoc} */
    public String mapToName(long id) throws ObligationProcessingException {
        return idToNameMap.get(id);
    }

    /** Reads the /etc/group file and loads it in to the map. */
    private void readEtcGroup() {
        File etcGroupFile = null;
        try {
            etcGroupFile = Files.getReadableFile("/etc/group");
        } catch (IOException e) {
            log.error(e.getMessage());
            return;
        }

        try {
            LineNumberReader etcGroupReader = new LineNumberReader(new FileReader(etcGroupFile));
            log.debug("Reading /etc/group file");

            String line = etcGroupReader.readLine();
            String trimmedLine;
            String[] entry;
            Long gid;
            String groupName;
            while (line != null) {
                trimmedLine = Strings.safeTrimOrNullString(line);
                if (trimmedLine != null && !trimmedLine.startsWith("#")) {
                    entry = trimmedLine.split(":");
                    try {
                        gid = Long.parseLong(entry[2]);
                        groupName = Strings.safeTrimOrNullString(entry[0]);
                        nameToIdMap.put(groupName, gid);
                        idToNameMap.put(gid, groupName);
                        log.trace("/etc/group line {} maps group name {} to GID {}", new Object[] {
                                etcGroupReader.getLineNumber(), groupName, gid });
                    } catch (NumberFormatException e) {
                        log.warn("The GID {} is not a valid, the /etc/group entry on line {} is being ignored",
                                entry[2], etcGroupReader.getLineNumber());
                    }
                } else {
                    log.trace("Ignoring /etc/group line {} because it empty or a comment", etcGroupReader
                            .getLineNumber());
                }
                line = etcGroupReader.readLine();
            }
        } catch (IOException e) {
            log.error("Error while reading /etc/group file", e);
        }
    }
}