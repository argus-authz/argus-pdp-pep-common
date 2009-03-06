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

package org.glite.authz.common.model;

import java.io.Serializable;
import java.util.List;

import net.jcip.annotations.NotThreadSafe;

import org.glite.authz.common.util.LazyList;

/** Response for an authorization {@link Request}. */
@NotThreadSafe
public class Response implements Serializable {

    /** Serial version UID. */
    private static final long serialVersionUID = 2315359866285813660L;
    
    /** The effective request that led to the given results. */
    private Request request;

    /** The results from an authorization request. */
    private LazyList<Result> results;

    /** Constructor. */
    public Response() {
        results = new LazyList<Result>();
    }
    
    /**
     * Gets the effective request that led to the given results.
     * 
     * @return effective request that led to the given results
     */
    public Request getRequest() {
        return request;
    }
    
    /**
     * Sets the effective request that led to the given results.
     * 
     * @param effectiveRequest effective request that led to the given results
     */
    public void setRequest(Request effectiveRequest) {
        request = effectiveRequest;
    }

    /**
     * Gets the results from an authorization request.
     * 
     * @return the results from an authorization request
     */
    public List<Result> getResults() {
        return results;
    }

    /** {@inheritDoc} */
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();

        stringBuilder.append("Response {");

        stringBuilder.append("results: [");
        for (Result result : results) {
            stringBuilder.append(result).append(", ");
        }

        stringBuilder.append("}");

        return stringBuilder.toString();
    }
}