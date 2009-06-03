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

import org.glite.authz.common.obligation.ObligationProcessingException;
import org.glite.authz.common.obligation.provider.dfpmap.IDMappingStrategy;
import org.jruby.ext.posix.Group;

/** Resolves a name against an /etc/group file and returns its GID. */
public class EtcGroupIDMappingStrategy implements IDMappingStrategy {

    /** {@inheritDoc} */
    public Integer mapToID(String name) throws ObligationProcessingException {
        Group group = PosixUtil.getGroupByName(name);
        if(group != null){
            return new Integer((int) group.getGID());
        }
        
        return null;
    }
}