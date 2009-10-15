/*
 * Copyright 2008 Members of the EGEE Collaboration.
 * See http://www.eu-egee.org/partners for details on the copyright holders. 
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
public final class Response implements Serializable {

    /** Serial version UID. */
    private static final long serialVersionUID = -3976503749290974107L;

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

    /** {@inheritDoc} */
    public int hashCode() {
        int hash = 13;

        hash = 31 * hash + (null == request ? 0 : request.hashCode());
        hash = 31 * hash + results.hashCode();

        return hash;
    }

    /** {@inheritDoc} */
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }

        if (obj == null || this.getClass() != obj.getClass()) {
            return false;
        }

        Response otherResponse = (Response) obj;

        boolean requestsEqual;
        if (request == null) {
            if (otherResponse.getRequest() == null) {
                requestsEqual = true;
            } else {
                requestsEqual = false;
            }
        } else {
            requestsEqual = request.equals(otherResponse.getRequest());
        }

        return results.equals(otherResponse.getResults()) && requestsEqual;
    }
}