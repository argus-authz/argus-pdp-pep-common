/*
 * Copyright 2008 EGEE Collaboration
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

import java.io.IOException;
import java.io.Reader;
import java.util.Map;
import java.util.Vector;

import org.glite.authz.common.obligation.provider.gridmap.GridMap.Entry;
import org.glite.authz.common.obligation.provider.gridmap.GridMap.GridMapKeyMatchFunction;

/** A parser of things nominally called gridmaps. */
public interface GridmapParser {

    /**
     * Gets the {@link GridMapKey} matching functions recommended to be used with the {@link Entry}s returned by this
     * parser.
     * 
     * @return {@link GridMapKey} matching functions recommended to be used with the {@link Entry}s returned by this
     *         parser
     */
    public Map<Class<? extends GridMapKey>, GridMapKeyMatchFunction> getKeyMatchFunctions();

    /**
     * Parses a grid map file. The returned mapped and its contained lists are thread safe and fail-fast collections.
     * The key to the map is the DN while the value is the list of account names to which that DN maps.
     * 
     * @param gridMapReader the reader providing the grid map file
     * 
     * @return the parsed grid map
     * 
     * @throws IOException thrown if the reader faults
     */
    public Vector<Entry> parse(Reader gridMapReader) throws IOException;
}