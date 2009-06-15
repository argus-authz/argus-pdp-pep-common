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
import java.io.IOException;
import java.io.LineNumberReader;
import java.util.HashMap;

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
    private HashMap<String, Integer> map;

    /** Constructor. */
    public EtcGroupIDMappingStrategy() {
        map = new HashMap<String, Integer>();
        readEtcGroup();
    }

    /** {@inheritDoc} */
    public Integer mapToID(String name) throws ObligationProcessingException {
        return map.get(name);
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

            String line = etcGroupReader.readLine();
            String trimmedLine;
            String[] entry;
            while (line != null) {
                trimmedLine = Strings.safeTrimOrNullString(line);
                if (trimmedLine != null && !trimmedLine.startsWith("#")) {
                    entry = trimmedLine.split(":");
                    log.debug("/etc/group line {} maps group name {} to GID {}", new Object[] {etcGroupReader.getLineNumber(), entry[0], entry[2]});
                    map.put(entry[0], new Integer(entry[2]));
                }else{
                    log.debug("Ignoring /etc/group line {} because it empty or a comment", etcGroupReader.getLineNumber());
                }
                line = etcGroupReader.readLine();
            }
        } catch (IOException e) {
            log.error("Error while reading /etc/group file", e);
        }
    }
}