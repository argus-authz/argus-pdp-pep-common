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

package org.glite.authz.common;

import java.io.PrintWriter;
import java.math.BigInteger;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.util.Strings;

/** A set of metrics kept about a running service. */
@ThreadSafe
public class ServiceMetrics {

    /** Java runtime. */
    Runtime runtime;

    /** ID for the service. */
    private String serviceId;

    /** Time the service started. */
    private long startupTime;

    /** Total number of completed requests to service */
    private BigInteger totalRequests;

    /** Accumulator of requests. */
    private int totalRequestAccumulator;

    /** Total number of request that error'ed out. */
    private BigInteger totalErrors;

    /** Accumulator of error'ed out requests. */
    private int totalErrorsAccumulator;

    /**
     * Constructor. Ê
     * 
     * @param id ID of the service whose metrics are being tracked
     */
    public ServiceMetrics(String id) {
        runtime = Runtime.getRuntime();
        serviceId = Strings.safeTrimOrNullString(id);
        startupTime = System.currentTimeMillis();
        totalRequests = new BigInteger("0");
        totalErrors = new BigInteger("0");
    }

    /**
     * Gets an identifier for the service whose metrics are being tracked.
     * 
     * @return the identifier for the service whose metrics are being tracked
     */
    public String getServiceId() {
        return serviceId;
    }

    /**
     * Gets the time that the service was started. The time is expressed in the system's default timezone.
     * 
     * @return time that PEP daemon was started
     */
    public long getServiceStartupTime() {
        return startupTime;
    }

    /**
     * Gets the total number of completed requests, successful or otherwise, serviced.
     * 
     * @return total number of completed requests
     */
    public BigInteger getTotalServiceRequests() {
        return totalRequests.add(integerToBigInteger(totalRequestAccumulator));
    }

    /** Adds one to the total number of requests. */
    public synchronized void incrementTotalServiceRequests() {
        totalRequestAccumulator = incrementMetric(totalRequests, totalRequestAccumulator);
    }

    /**
     * Gets the total number of requests that error'ed out.
     * 
     * @return total number of requests that error'ed out
     */
    public BigInteger getTotalServiceRequestErrors() {
        return totalErrors.add(integerToBigInteger(totalErrorsAccumulator));
    }

    /** Adds one to the total number of requests that have error'ed out. */
    public synchronized void incrementTotalServiceRequestErrors() {
        totalErrorsAccumulator = incrementMetric(totalErrors, totalErrorsAccumulator);
    }

    /**
     * Prints metric information to the output writer. The following lines are printed:
     * <ul>
     * <li>service: <i>service_id</i></li>
     * <li>start time: <i>service_start_time</i></li>
     * <li>number of processors: <i>number_of_cpu_cores</i></li>
     * <li>memory usage: <i>used_megabytes</i>MB</li>
     * <li>total requests: <i>total_requests</i></li>
     * <li>total completed requests: <i>total_completed_requests</i></li>
     * <li>total request errors: <i>total_errors_requests</i></li>
     * </ul>
     * 
     * @param writer writer to which metrics are printed
     */
    public void printServiceMetrics(PrintWriter writer) {
        long usedMemory = (runtime.totalMemory() - runtime.freeMemory()) / 1048576;

        writer.println("service: " + serviceId);
        writer.println("start time: " + startupTime);
        writer.println("number of processors: " + runtime.availableProcessors());
        writer.println("memory usage: " + usedMemory + "MB");
        writer.println("total requests: " + getTotalServiceRequests().toString());
        writer.println("total completed requests: "
                + getTotalServiceRequests().subtract(getTotalServiceRequestErrors()).toString());
        writer.println("total request errors: " + getTotalServiceRequestErrors());

    }

    /**
     * Increments a measurement stored in a BigInteger but with a integer accumulator serving as a temporary bucket.
     * This avoids the cost of creating new BigIntegers, which are immutable, every time the metric is incremented.
     * 
     * @param store the BigInteger store
     * @param accumulator the temporary accumulation bucket
     * 
     * @return new value for the accumulator
     */
    private int incrementMetric(BigInteger store, int accumulator) {
        if (accumulator == Integer.MAX_VALUE - 1) {
            store = store.add(integerToBigInteger(accumulator++));
            return 0;
        } else {
            return accumulator + 1;
        }
    }

    /**
     * Converted an integer in to a {@link BigInteger}.
     * 
     * @param integer integer to convert
     * 
     * @return BigInteger form of the integer
     */
    private BigInteger integerToBigInteger(Integer integer) {
        return new BigInteger(Integer.toString(integer));
    }
}