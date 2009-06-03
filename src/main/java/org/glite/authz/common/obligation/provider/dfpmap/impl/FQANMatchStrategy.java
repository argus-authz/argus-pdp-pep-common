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

import java.util.ArrayList;

import org.glite.authz.common.obligation.provider.dfpmap.FQAN;

/** A matching strategy used to match {@link FQAN}s against other FQANs, possibly containing the wildcard '*'. */
public class FQANMatchStrategy implements DFPMMatchStrategy<FQAN> {

    /** {@inheritDoc} */
    public boolean isMatch(String dfpmKey, FQAN candidate) {
        FQAN target = FQAN.parseFQAN(dfpmKey);
        
        if (target instanceof FQAN && candidate instanceof FQAN) {
            FQAN targetFQAN = (FQAN) target;
            FQAN candidateFQAN = (FQAN) candidate;

            if (targetFQAN.getAttributeGroupId().endsWith("*")) {
                String targetGroupIDRegex = targetFQAN.getAttributeGroupId().replace("*", ".+");
                if (!candidateFQAN.getAttributeGroupId().matches(targetGroupIDRegex)) {
                    return false;
                }
            } else {
                if (!candidateFQAN.getAttributeGroupId().equals(targetFQAN.getAttributeGroupId())) {
                    return false;
                }
            }

            ArrayList<String> attributeIds = new ArrayList<String>();
            attributeIds.addAll(targetFQAN.getAttributeIds());
            attributeIds.addAll(candidateFQAN.getAttributeIds());
            
            for(String id : attributeIds){
                if (!attributeMatches(targetFQAN.getAttributeById(id), candidateFQAN.getAttributeById(id))) {
                    return false;
                }
            }

            return true;
        }

        return false;
    }

    /**
     * Checks whether an attribute matches another attribute.
     * 
     * @param target the attribute the candidate is checked against
     * @param candidate the attribute checked against the target
     * 
     * @return true if the candidate matches the target, false if not
     */
    private boolean attributeMatches(FQAN.Attribute target, FQAN.Attribute candidate) {
        if(target == null && candidate == null){
            return true;
        }
        
        if (candidate == null) {
            if (target.getValue().equals(FQAN.Attribute.NULL_VALUE)) {
                return true;
            }
            return false;
        }
        
        if(target == null){
            if(candidate.getValue().equals(FQAN.Attribute.NULL_VALUE)){
                return true;
            }
            return false;
        }

        if (!target.getId().equals(candidate.getId())) {
            return false;
        }

        String valueMatch = target.getValue().replace("*", ".+");
        return candidate.getValue().matches(valueMatch);
    }
}