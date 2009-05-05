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

import java.util.List;
import java.util.Map;

import net.jcip.annotations.ThreadSafe;

/**
 * A grid map maps a given target to a set of IDs. It consists of an ordered list of {@link Entry} objects and a
 * collection of {@link GridMapKeyMatchFunction}. The {@link GridMapKeyMatchFunction} are indexed by the class types of
 * the {@link Entry#key} types.
 * 
 * A given target activates a mapping if the {@link GridMapKeyMatchFunction} associate with an {@link Entry} indicates
 * that the target matches the {@link Entry#key}. A mapping can stop at the first match, at which point only the IDs
 * associated with that particular entry are returned, or can continue through all entries. In the later case the list
 * of returned IDs are is the concatenated list of IDs from each match. Duplicates IDs are not removed.
 */
@ThreadSafe
public interface GridMap {

    /**
     * Gets the ordered, unmodifiable, list of map entries.
     * 
     * @return ordered list of map entries
     */
    public List<Entry> getMapEntries();

    /**
     * Gets the unmodifiable collection of registered {@link GridMapKeyMatchFunction} indexed by the {@link GridMapKey}
     * types upon which the operate.
     * 
     * @return registered {@link GridMapKeyMatchFunction}
     */
    public Map<Class<? extends GridMapKey>, GridMapKeyMatchFunction> getKeyMatchFunctions();

    /**
     * Maps a given target to a set of IDs.
     * 
     * @param key the target to map
     * @param matchMultiple whether to allow more than one match
     * 
     * @return the list of IDs to which the given target maps
     */
    public List<String> map(GridMapKey key, boolean matchMultiple);

    /** Represents an entry in a grid map file. */
    @ThreadSafe
    public static interface Entry {

        /**
         * Gets the key that maps to a list of IDs.
         * 
         * @return key that maps to a list of IDs
         */
        public GridMapKey getKey();

        /**
         * Gets the IDs that are mapped to a given name.
         * 
         * @return IDs that are mapped to a given name
         */
        public List<String> getIds();
    }

    /** Function that matches a grid map name against a target string. */
    @ThreadSafe
    public static interface GridMapKeyMatchFunction {

        /**
         * Checks whether the grid map entry name matches the target.
         * 
         * @param target the target that the compared key must match
         * @param candidate the candidate key that must match the target
         * 
         * @return true of the target matches the entry string, false if not
         */
        public boolean matches(GridMapKey target, GridMapKey candidate);
    }
}