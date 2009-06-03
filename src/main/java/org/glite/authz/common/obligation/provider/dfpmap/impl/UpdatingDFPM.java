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

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.glite.authz.common.obligation.provider.dfpmap.DFPM;

/**
 * A {@link DFPM} implementation that periodically re-reads a mapping file and, if changes have occurred, updates the
 * mapping.  Such an update does not effect any 
 */
public class UpdatingDFPM implements DFPM {

    /** Delegate that is refreshed every period. */
    private DFPM delegate;

    public UpdatingDFPM(DFPMFactory factory, String mappingFile, int refreshPeriod) {

    }

    /** {@inheritDoc} */
    public boolean isDNMapEntry(String key) {
        return delegate.isDNMapEntry(key);
    }

    /** {@inheritDoc} */
    public boolean isFQANMapEntry(String key) {
        return delegate.isFQANMapEntry(key);
    }

    /** {@inheritDoc} */
    public void clear() {
        delegate.clear();
    }

    /** {@inheritDoc} */
    public boolean containsKey(Object key) {
        return delegate.containsKey(key);
    }

    /** {@inheritDoc} */
    public boolean containsValue(Object value) {
        return delegate.containsValue(value);
    }

    /** {@inheritDoc} */
    public Set<java.util.Map.Entry<String, List<String>>> entrySet() {
        return delegate.entrySet();
    }

    /** {@inheritDoc} */
    public List<String> get(Object key) {
        return delegate.get(key);
    }

    /** {@inheritDoc} */
    public boolean isEmpty() {
        return delegate.isEmpty();
    }

    /** {@inheritDoc} */
    public Set<String> keySet() {
        return delegate.keySet();
    }

    /** {@inheritDoc} */
    public List<String> put(String key, List<String> value) {
        return delegate.put(key, value);
    }

    /** {@inheritDoc} */
    public void putAll(Map<? extends String, ? extends List<String>> map) {
        delegate.putAll(map);
    }

    /** {@inheritDoc} */
    public List<String> remove(Object key) {
        return delegate.remove(key);
    }

    /** {@inheritDoc} */
    public int size() {
        return delegate.size();
    }

    /** {@inheritDoc} */
    public Collection<List<String>> values() {
        return delegate.values();
    }
    
    public static interface DFPMFactory{
        
        public DFPM build();
    }
}