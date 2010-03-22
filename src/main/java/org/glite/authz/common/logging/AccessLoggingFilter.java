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

package org.glite.authz.common.logging;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** A filter that writes access log messages to the {@value LoggingConstants#ACCESS_CATEGORY} logging category. */
public class AccessLoggingFilter implements Filter {
    
    /** Access log. */
    private final Logger accessLog = LoggerFactory.getLogger(LoggingConstants.ACCESS_CATEGORY);

    /** {@inheritDoc} */
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
            ServletException {
        accessLog.info(new AccessLogEntry((HttpServletRequest) request).toString());
        chain.doFilter(request, response);
    }

    /** {@inheritDoc} */
    public void init(FilterConfig filterConfig) throws ServletException {
        // do nothing
    }

    /** {@inheritDoc} */
    public void destroy() {
        // do nothing
    }
}
