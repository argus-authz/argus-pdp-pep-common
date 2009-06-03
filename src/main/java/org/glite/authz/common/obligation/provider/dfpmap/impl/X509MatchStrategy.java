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

import javax.security.auth.x500.X500Principal;

/** A matching strategy for {@link X500Principal}. */
public class X509MatchStrategy implements DFPMMatchStrategy<X500Principal>{

    /** {@inheritDoc} */
    public boolean isMatch(String dfpmKey, X500Principal candidate) {
        try{
            X500Principal target = new X500Principal(dfpmKey);
            return target.equals(candidate);
        }catch(IllegalArgumentException e){
            return false;
        }
    }
}