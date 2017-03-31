/*
 * Copyright (c) Members of the EGEE Collaboration. 2006-2010.
 * See http://www.eu-egee.org/partners/ for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.glite.authz.common;

import java.io.PrintWriter;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.util.Strings;

import org.joda.time.DateTime;
import org.joda.time.chrono.ISOChronology;

/** A set of metrics kept about a running service. */
@ThreadSafe
public class ServiceMetrics {

    /** Java runtime. */
    private Runtime runtime;

    /** ID for the service. */
    private String serviceId;
    
    /** Version of the service */
    private String serviceVersion;

    /** Time the service started. */
    private long startupTime;

    /** Total number of completed requests to service. */
    private long totalRequests;

    /** Total number of request that error'ed out. */
    private long totalErrors;

    /**
     * Constructor
     * 
     * @param id
     *            ID of the service whose metrics are being tracked
     * @param version
     *            Version of the service whose metrics are being tracked
     */
    public ServiceMetrics(String id, String version) {
        runtime= Runtime.getRuntime();
        serviceId= Strings.safeTrimOrNullString(id);
        serviceVersion= Strings.safeTrimOrNullString(version);
        startupTime= System.currentTimeMillis();
        totalRequests= 0;
        totalErrors= 0;
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
     * Gets the time that the service was started. The time is expressed in the
     * system's default timezone.
     * 
     * @return time that PEP daemon was started
     */
    public long getServiceStartupTime() {
        return startupTime;
    }

    /**
     * Gets the total number of completed requests, successful or otherwise,
     * serviced.
     * 
     * @return total number of completed requests
     */
    public long getTotalServiceRequests() {
        return totalRequests;
    }

    /** Adds one to the total number of requests. */
    public void incrementTotalServiceRequests() {
        totalRequests++;
    }

    /**
     * Gets the total number of requests that error'ed out.
     * 
     * @return total number of requests that error'ed out
     */
    public long getTotalServiceRequestErrors() {
        return totalErrors;
    }

    /** Adds one to the total number of requests that have error'ed out. */
    public void incrementTotalServiceRequestErrors() {
        totalErrors++;
    }

    /**
     * Prints metric information to the output writer. The following lines are
     * printed:
     * <ul>
     * <li>Status: OK</li>
     * <li>Service: <i>service_id</i></li>
     * <li>ServiceVersion: <i>service_version</i></li>
     * <li>ServiceStartupTime: <i>service_start_time</i></li>
     * <li>ServiceStartupTimeMillis: <i>service_start_timemillis</i></li>
     * <li>NumberOfProcessors: <i>number_of_cpu_cores</i></li>
     * <li>MaxMemory: <i>max_memory_bytes</i> bytes</li>
     * <li>UsedMemory: <i>used_memory_bytes</i> bytes</li>
     * <li>TotalRequests: <i>total_requests</i></li>
     * <li>TotalCompletedRequests: <i>total_completed_requests</i></li>
     * <li>TotalRequestErrors: <i>total_errors_requests</i></li>
     * </ul>
     * 
     * @param writer
     *            writer to which metrics are printed
     */
    public void printServiceMetrics(PrintWriter writer) {
        // long usedMemory = (runtime.totalMemory() - runtime.freeMemory()) /
        // 1048576;
        long maxMemory= runtime.maxMemory();
        long usedMemory= (runtime.totalMemory() - runtime.freeMemory());

        writer.println("Status: OK");
        writer.println("Service: " + serviceId);
        writer.println("ServiceVersion: " + serviceVersion);
        writer.println("ServiceStartupTime: " + new DateTime(startupTime).withChronology(ISOChronology.getInstanceUTC()));
        writer.println("ServiceStartupTimeMillis: " + startupTime);
        writer.println("NumberOfProcessors: " + runtime.availableProcessors());
        writer.println("MaxMemory: " + maxMemory + " bytes");
        writer.println("UsedMemory: " + usedMemory + " bytes");
        writer.println("TotalRequests: " + getTotalServiceRequests());
        writer.println("TotalCompletedRequests: "
                + (getTotalServiceRequests() - getTotalServiceRequestErrors()));
        writer.println("TotalRequestErrors: " + getTotalServiceRequestErrors());

    }
}
