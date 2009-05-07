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

package org.glite.authz.common.obligation.provider.gridmap;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import net.jcip.annotations.ThreadSafe;

/** A very basic implementation of a {@link GridMap}. */
@ThreadSafe
public class BasicGridMap implements GridMap {

    /** An unmodifiable list of entries representing a grid map. */
    private List<Entry> mapEntries;

    /** An unmodifiable collection of {@link GridMapKey} matching functions indexed by classes upon which they operate. */
    private Map<Class<? extends GridMapKey>, GridMapKeyMatchFunction> keyMatchFunctions;

    /**
     * Constructor.
     * 
     * @param entries grid map entries
     * @param matchFunctions{@link GridMapKey} matching functions indexed by classes upon which they operate
     * 
     */
    public BasicGridMap(List<Entry> entries, Map<Class<? extends GridMapKey>, GridMapKeyMatchFunction> matchFunctions) {
        mapEntries = Collections.unmodifiableList(entries);
        keyMatchFunctions = Collections.unmodifiableMap(matchFunctions);
    }

    /**
     * Gets the ordered, unmodifiable, list of map entries.
     * 
     * @return ordered list of map entries
     */
    public List<Entry> getMapEntries() {
        return mapEntries;
    }

    /**
     * Gets the unmodifiable collection of registered {@link GridMapKeyMatchFunction} indexed by the {@link GridMapKey}
     * types upon which the operate.
     * 
     * @return registered {@link GridMapKeyMatchFunction}
     */
    public Map<Class<? extends GridMapKey>, GridMapKeyMatchFunction> getKeyMatchFunctions() {
        return keyMatchFunctions;
    }
}