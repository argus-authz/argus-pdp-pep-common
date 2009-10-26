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

import org.glite.authz.common.obligation.ObligationProcessingException;

/** Strategy used to map a login or group name to its respective ID. */
public interface IDMappingStrategy {

    /**
     * Maps the given name to its respective ID.
     * 
     * @param name name to map
     * 
     * @return corresponding ID or null if there was no mapping
     * 
     * @throws ObligationProcessingException thrown if there is a problem mapping the name to the ID
     */
    public Long mapToID(String name) throws ObligationProcessingException;
    
    /**
     * Maps a given ID to its respective name.
     * 
     * @param id ID to map
     * 
     * @return corresponding name or null if there was no mapping
     * 
     * @throws ObligationProcessingException thrown if there is a problem mapping the name to the ID
     */
    public String mapToName(long id) throws ObligationProcessingException;
}