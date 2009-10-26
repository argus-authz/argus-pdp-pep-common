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

import java.util.HashMap;
import java.util.Map;

import org.glite.authz.common.obligation.ObligationProcessingException;
import org.glite.authz.common.obligation.provider.dfpmap.IDMappingStrategy;

/** Resolves a name against a preconfigured set of name to ID mappings. */
public class MemoryBackedIDMappingStrategy implements IDMappingStrategy {

    /** Map from name to ID. */
    private Map<String, Long> nameToIdMap;

    /** Map from ID to Name. */
    private Map<Long, String> idToNameMap;

    /**
     * Constructor.
     * 
     * @param mappings name to ID mappings
     */
    public MemoryBackedIDMappingStrategy(Map<String, Long> mappings) {
        if (mappings == null) {
            throw new IllegalArgumentException("Name to ID map may not be null");
        }
        nameToIdMap = new HashMap<String, Long>(mappings);
        idToNameMap = new HashMap<Long, String>();

        for (Map.Entry<String, Long> mappingEntry : nameToIdMap.entrySet()) {
            idToNameMap.put(mappingEntry.getValue(), mappingEntry.getKey());
        }
    }

    /** {@inheritDoc} */
    public Long mapToID(String name) throws ObligationProcessingException {
        return nameToIdMap.get(name);
    }

    /** {@inheritDoc} */
    public String mapToName(long id) throws ObligationProcessingException {
        return idToNameMap.get(id);
    }
}