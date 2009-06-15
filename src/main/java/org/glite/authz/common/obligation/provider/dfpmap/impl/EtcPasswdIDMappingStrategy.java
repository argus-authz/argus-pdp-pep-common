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

/** Resolves a name against an /etc/passwd file and returns its UID. */
public class EtcPasswdIDMappingStrategy implements IDMappingStrategy {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(EtcPasswdIDMappingStrategy.class);

    /** Map from login name to UID. */
    private HashMap<String, Integer> map;

    /** Constructor. */
    public EtcPasswdIDMappingStrategy() {
        map = new HashMap<String, Integer>();
        readEtcPasswd();
    }

    /** {@inheritDoc} */
    public Integer mapToID(String name) throws ObligationProcessingException {
        return map.get(name);
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

            String line = etcPasswdReader.readLine();
            String trimmedLine;
            String[] entry;
            while (line != null) {
                trimmedLine = Strings.safeTrimOrNullString(line);
                if (trimmedLine != null && !trimmedLine.startsWith("#")) {
                    entry = trimmedLine.split(":");
                    log.debug("/etc/passwd line {} maps login name {} to GID {}", new Object[] {etcPasswdReader.getLineNumber(), entry[0], entry[2]});
                    map.put(entry[0], new Integer(entry[2]));
                }else{
                    log.debug("Ignoring /etc/passwd line {} because it empty or a comment", etcPasswdReader.getLineNumber());
                }
                line = etcPasswdReader.readLine();
            }
        } catch (IOException e) {
            log.error("Error while reading /etc/passwd file", e);
        }
    }
}