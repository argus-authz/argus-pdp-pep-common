
package org.glite.authz.common.obligation.provider.gridmap;

import java.util.List;

import net.jcip.annotations.ThreadSafe;

/** Represents an entry in a grid map file. */
@ThreadSafe
public class BasicGridMapEntry implements GridMap.Entry {

    /** Key to a list of IDs. */
    private GridMapKey key;

    /** IDs mapped to a key. */
    private List<String> ids;

    /**
     * Constructor.
     * 
     * @param name the name mapped to a list of IDs
     * @param ids the IDs mapped to a name
     */
    public BasicGridMapEntry(GridMapKey key, List<String> ids) {
        this.key = key;
        if (this.key == null) {
            throw new IllegalArgumentException("Kay may not be null or empty");
        }

        this.ids = ids;
        if (this.ids == null) {
            throw new IllegalArgumentException("List of IDs may not be null");
        }
    }

    /**
     * Gets the key that maps to a list of IDs.
     * 
     * @return key that maps to a list of IDs
     */
    public GridMapKey getKey() {
        return key;
    }

    /**
     * Gets the IDs that are mapped to a given name.
     * 
     * @return IDs that are mapped to a given name
     */
    public List<String> getIds() {
        return ids;
    }

    /** {@inheritDoc} */
    public String toString() {
        return "{key:" + key + ", value:" + ids + "}";
    }

    /** {@inheritDoc} */
    public int hashCode() {
        int hash = 13;

        hash = 31 * hash + key.hashCode();
        hash = 31 * hash + ids.hashCode();

        return hash;
    }

    /** {@inheritDoc} */
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }

        if (obj == null) {
            return false;
        }

        if (obj instanceof BasicGridMapEntry) {
            BasicGridMapEntry otherEntry = (BasicGridMapEntry) obj;
            return key.equals(otherEntry.getKey()) && ids.equals(otherEntry.getIds());
        }

        return false;
    }
}