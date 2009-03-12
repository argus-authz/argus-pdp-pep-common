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

import java.io.File;
import java.io.IOException;
import java.util.Vector;
import java.util.concurrent.ConcurrentMap;

import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Result;
import org.glite.authz.common.obligation.AbstractObligationHandler;
import org.glite.authz.common.obligation.ObligationProcessingException;
import org.glite.authz.common.util.Files;
import org.opensaml.util.storage.StorageService;

/**
 * An obligation handler that creates a mapping between the subject ID of the request and a POSIX account (UID/GIDs).
 * This mapping information is provided in a gridmap file.
 */
public class GridmapAccountMapping extends AbstractObligationHandler {

    private StorageService<String, String> storageService;

    private File gridmapFile;

    private ConcurrentMap<FullyQualifiedName, Vector<String>> gridmap;

    /**
     * Constructor. Obligation has the lowest precedence
     * 
     * @param obligationId ID of the handled obligation
     * @param gridMapFilePath the path to the gridmap file
     * @param store the backing store for the subject to POSIX account mapping
     */
    protected GridmapAccountMapping(String obligationId, String gridMapFilePath, StorageService<String, String> store) {
        this(obligationId, Integer.MIN_VALUE, gridMapFilePath, store);
    }

    /**
     * Constructor.
     * 
     * @param obligationId ID of the handled obligation
     * @param handlerPrecedence precedence of this handler *
     * @param gridMapFilePath the path to the gridmap file
     * @param store the backing store for the subject to POSIX account mapping
     */
    protected GridmapAccountMapping(String obligationId, int handlerPrecedence, String gridMapFilePath,
            StorageService<String, String> store) {
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
        // TODO Auto-generated method stub

    }
}