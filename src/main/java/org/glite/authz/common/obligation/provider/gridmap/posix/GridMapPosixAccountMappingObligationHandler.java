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

package org.glite.authz.common.obligation.provider.gridmap.posix;

import java.io.File;
import java.io.IOException;
import java.util.Vector;
import java.util.concurrent.ConcurrentMap;

import org.glite.authz.common.model.AttributeAssignment;
import org.glite.authz.common.model.Obligation;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Result;
import org.glite.authz.common.obligation.AbstractObligationHandler;
import org.glite.authz.common.obligation.ObligationProcessingException;
import org.glite.authz.common.obligation.provider.gridmap.GridMapKey;
import org.glite.authz.common.util.Files;
import org.glite.authz.common.util.Strings;
import org.opensaml.util.storage.StorageService;

/**
 * An obligation handler that creates a mapping between the subject ID of the request and a POSIX account (UID/GIDs).
 * This mapping information is provided in a gridmap file.
 */
public class GridMapPosixAccountMappingObligationHandler extends AbstractObligationHandler {

    /** The URI, {@value}, of the obligation used to indicate that an grid map based account mapping should occur. */
    public static final String MAPPING_OB_ID = "x-posix-acount-map";

    /** The URI, {@value}, of the username obligation. */
    public static final String USERNAME_OB_ID = "http://authz-interop.org/xacml/obligation/username";

    /** The URI, {@value}, of the username obligation attribute. */
    public static final String USERNAME_ATTRIB_ID = "http://authz-interop.org/xacml/attribute/username";

    /** The URI, {@value}, of the UID/GID obligation. */
    public static final String UIDGID_OB_ID = "http://authz-interop.org/xacml/obligation/uidgid";

    /** The URI, {@value}, of the secondary GIDs obligation. */
    public static final String SECONDARY_GIDS_OB_ID = "http://authz-interop.org/xacml/obligation/secondary-gids";

    /** The URI, {@value}, of the UID obligation attribute. */
    public static final String UID_ATTRIB_ID = "http://authz-interop.org/xacml/attribute/posix-uid";

    /** The URI, {@value}, of the GID obligation attribute. */
    public static final String GID_ATTRIB_ID = "http://authz-interop.org/xacml/attribute/posix-gid";

    
    private StorageService<String, String> storageService;

    private File gridmapFile;

    private ConcurrentMap<GridMapKey, Vector<String>> gridmap;

    /**
     * Constructor. Obligation has the lowest precedence
     * 
     * @param obligationId ID of the handled obligation
     * @param gridMapFilePath the path to the gridmap file
     * @param store the backing store for the subject to POSIX account mapping
     */
    protected GridMapPosixAccountMappingObligationHandler(String obligationId, String gridMapFilePath,
            StorageService<String, String> store) {
        this(obligationId, Integer.MIN_VALUE, gridMapFilePath, store);
    }

    /**
     * Constructor.
     * 
     * @param obligationId ID of the handled obligation
     * @param handlerPrecedence precedence of this handler
     * @param gridMapFilePath the path to the gridmap file
     * @param store the backing store for the subject to POSIX account mapping
     */
    protected GridMapPosixAccountMappingObligationHandler(String obligationId, int handlerPrecedence,
            String gridMapFilePath, StorageService<String, String> store) {
        super(obligationId, handlerPrecedence);

        try {
            gridmapFile = Files.getReadableFile(gridMapFilePath);
        } catch (IOException e) {
            throw new IllegalArgumentException(e.getMessage());
        }

        if (store == null) {
            throw new IllegalArgumentException("Storage service may not be null");
        }
        storageService = store;
    }

    /** {@inheritDoc} */
    public void evaluateObligation(Request request, Result result) throws ObligationProcessingException {

        
        
    }

    protected void addUIDGIDObligations(Result result, PosixAccount account) {
        Obligation mappingOb = null;
        for (Obligation ob : result.getObligations()) {
            if (ob.getId().equals(MAPPING_OB_ID)) {
                mappingOb = ob;
            }
        }
        result.getObligations().remove(mappingOb);

        Obligation usernameOb = buildUsernameObligation(account);
        if (usernameOb != null) {
            result.getObligations().add(usernameOb);
        }

        Obligation uidgidOb = buildUIDGIDObligation(account);
        result.getObligations().add(uidgidOb);

        Obligation secondaryGIDs = buildSecondaryGIDsObligation(account);
        if (secondaryGIDs != null) {
            result.getObligations().add(secondaryGIDs);
        }
    }

    /**
     * Creates an {@value #USERNAME_OB_ID} obligation if the given {@link PosixAccount} provides a username.
     * 
     * @param account the account used to populate the obligation
     * 
     * @return the created obligation or null if the {@link PosixAccount} did not contain a username
     */
    protected Obligation buildUsernameObligation(PosixAccount account) {
        String username = Strings.safeTrimOrNullString(account.getUsername());
        if (username == null) {
            return null;
        }

        Obligation obligation = new Obligation();
        obligation.setFulfillOn(Result.DECISION_PERMIT);
        obligation.setId(USERNAME_OB_ID);

        AttributeAssignment attributeAssignment = new AttributeAssignment();
        attributeAssignment.setAttributeId(USERNAME_ATTRIB_ID);
        attributeAssignment.getValues().add(username);
        obligation.getAttributeAssignments().add(attributeAssignment);

        return obligation;
    }

    /**
     * Creates an {@value #UIDGID_OB_ID} obligation with information in the given {@link PosixAccount}.
     * 
     * @param account the account used to populate the obligation
     * 
     * @return the created obligation
     */
    protected Obligation buildUIDGIDObligation(PosixAccount account) {
        Obligation obligation = new Obligation();
        obligation.setFulfillOn(Result.DECISION_PERMIT);
        obligation.setId(UIDGID_OB_ID);

        AttributeAssignment attributeAssignment = new AttributeAssignment();
        attributeAssignment.setAttributeId(UID_ATTRIB_ID);
        attributeAssignment.getValues().add(Long.toString(account.getUID()));
        obligation.getAttributeAssignments().add(attributeAssignment);

        if (!account.getGIDs().isEmpty()) {
            attributeAssignment = new AttributeAssignment();
            attributeAssignment.setAttributeId(GID_ATTRIB_ID);
            attributeAssignment.getValues().add(account.getGIDs().get(0).toString());
            obligation.getAttributeAssignments().add(attributeAssignment);
        }

        return obligation;
    }

    /**
     * Creates an {@value #SECONDARY_GIDS_OB_ID} obligation if the given {@link PosixAccount} has more than one GID.
     * 
     * @param account the account used to populate the obligation
     * 
     * @return the created obligation or null if the {@link PosixAccount} did not contain a username
     */
    protected Obligation buildSecondaryGIDsObligation(PosixAccount account) {
        if (account.getGIDs().size() < 2) {
            return null;
        }
        Obligation obligation = new Obligation();
        obligation.setFulfillOn(Result.DECISION_PERMIT);
        obligation.setId(SECONDARY_GIDS_OB_ID);

        AttributeAssignment attributeAssignment;
        for (int i = 1; i < account.getGIDs().size(); i++) {
            attributeAssignment = new AttributeAssignment();
            attributeAssignment.setAttributeId(GID_ATTRIB_ID);
            attributeAssignment.getValues().add(account.getGIDs().get(i).toString());
            obligation.getAttributeAssignments().add(attributeAssignment);
        }

        return obligation;
    }
}