/*
 * Copyright 2010 Members of the EGEE Collaboration.
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
package org.glite.authz.common.http;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.glite.authz.common.util.Strings;

/** A simple filter that password protects a request. */
public class PasswordProtectFilter implements Filter {
    
    /** HTTP request parameter that carries the password. */
    public static final String PASSWORD_PARAM_NAME = "password";
    
    /** The expected request password. */
    private final String requestPassword;

    /**
     * Constructor.
     * 
     * @param password the request password
     */
    public PasswordProtectFilter(String password){
        requestPassword = Strings.safeTrimOrNullString(password);
    }
    
    /** {@inheritDoc} */
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
            ServletException {
        String password = Strings.safeTrimOrNullString(request.getParameter(PASSWORD_PARAM_NAME));
        
        if(requestPassword != null && !requestPassword.equals(password)){
            ((HttpServletResponse)response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }
        
        chain.doFilter(request, response);
    }

    /** {@inheritDoc} */
    public void init(FilterConfig filterConfig) throws ServletException {
        
    }
    
    /** {@inheritDoc} */
    public void destroy() {
        
    }
}