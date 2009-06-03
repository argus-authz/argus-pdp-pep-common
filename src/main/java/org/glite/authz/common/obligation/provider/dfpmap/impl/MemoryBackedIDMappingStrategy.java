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

import java.util.HashMap;
import java.util.Map;

import org.glite.authz.common.obligation.ObligationProcessingException;
import org.glite.authz.common.obligation.provider.dfpmap.IDMappingStrategy;

/** Resolves a name against a preconfigured set of name to ID mappings. */
public class MemoryBackedIDMappingStrategy implements IDMappingStrategy {
    
    /** Configured name to ID mappings. */
    private HashMap<String, Integer> mappings;

    /**
     * Constructor.
     * 
     * @param mappings name to ID mappings
     */
    public MemoryBackedIDMappingStrategy(Map<String, Integer> mappings){
        if(mappings == null){
            throw new IllegalArgumentException("Name to ID map may not be null");
        }
        this.mappings = new HashMap<String, Integer>(mappings);
    }
    
    /** {@inheritDoc} */
    public Integer mapToID(String name) throws ObligationProcessingException {
        return mappings.get(name);
    }
}