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

package org.glite.authz.common.http;

import java.io.IOException;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.UnknownHostException;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.httpclient.methods.GetMethod;
import org.glite.authz.common.util.Strings;
import org.opensaml.ws.soap.client.http.HttpClientBuilder;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;

/**
 * A command line tool used to communicate with {@link JettyAdminService}.
 * 
 * Command line arguments are, in order:
 * <ul>
 * <li><em>hostname</em> - hostname to which to connect</li>
 * <li><em>port</em> - port to which to connect</li>
 * <li><em>command</em> - admin command to execute</li>
 * <li><em>password</em> - admin command password</li>
 * </ul>
 */
public class JettyAdminServiceCLI {

    /** Successful return code: {@value} . */
    public static final int RC_SUCCESS = 0;

    /** Bad command line arguments return code: {@value} . */
    public static final int RC_BAD_ARGUMENTS = 1;

    /** HTTP connection error return code: {@value} . */
    public static final int RC_CTX = 2;

    /** Invalid command return code: {@value} . */
    public static final int RC_INVALID_COMMAND = 3;

    /** Unauthorized return code: {@value} . */
    public static final int RC_UNAUTHORIZED = 4;

    /** Unknown error return code: {@value} . */
    public static final int RC_UNKNOWN = 100;

    /**
     * Run the admin client.
     * 
     * @param args command line arguments
     */
    public static void main(String[] args) {
        if (args.length < 3) {
            exit("Invalid command line arguments", RC_BAD_ARGUMENTS);
        }

        disableLibraryLogging();

        String host = parseHost(args[0]);
        int port = parsePort(args[1]);
        String command = parseCommand(args[2]);
        String password = null;
        
        if(args.length == 4){
            password = Strings.safeTrimOrNullString(args[3]);
        }
        
        executeCommand(host, port, command, password);
        exit(null, RC_SUCCESS);
    }

    /** Disables logging messages from all dependent libraries. */
    private static void disableLibraryLogging() {
        LoggerContext lc = (LoggerContext) LoggerFactory.getILoggerFactory();
        Logger rootLogger = lc.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        rootLogger.setLevel(Level.OFF);
    }

    /**
     * Parses the hostname command line argument. Checks that the argument is a valid hostname.
     * 
     * @param hostArgument the command line hostname argument
     * 
     * @return the hostname
     */
    private static String parseHost(String hostArgument) {
        try {
            InetAddress[] addresses = InetAddress.getAllByName(hostArgument);
            return addresses[0].getHostName();
        } catch (UnknownHostException e) {
            exit("The host argument is not a valid hostname or IP address", RC_BAD_ARGUMENTS);
        }

        return null;
    }

    /**
     * Parses the port command line argument. Checks that the port command line argument is a valid integer and between
     * 1 and 65535 (valid port numbers).
     * 
     * @param portArgument the command line port argument
     * 
     * @return the port
     */
    private static int parsePort(String portArgument) {
        try {
            int port = Integer.parseInt(portArgument);
            if (port < 1 || port > 65535) {
                exit("Port number is not valid", RC_BAD_ARGUMENTS);
            }
            return port;
        } catch (NumberFormatException e) {
            exit("Port number is not valid", RC_BAD_ARGUMENTS);
        }

        return 0;
    }

    /**
     * Parses the command command line argument. Checks that the argument is not null.
     * 
     * @param commandArgument the command line command argument
     * 
     * @return the command
     */
    private static String parseCommand(String commandArgument) {
        String argument = Strings.safeTrimOrNullString(commandArgument);
        if (argument == null) {
            exit("Command argument is not valid", RC_BAD_ARGUMENTS);
        }

        return argument;
    }

    /**
     * Executes the service command. Also checks to ensure the HTTP return code was 200.
     * 
     * @param host host to which to connect
     * @param port port to which to connect
     * @param command command sent to the admin service
     * @param password admin command password, may be null
     */
    private static void executeCommand(String host, int port, String command, String password) {
        HttpClientBuilder clientBuilder = new HttpClientBuilder();
        HttpClient httpClient = clientBuilder.buildClient();

        GetMethod getMethod = new GetMethod("http://" + host + ":" + port + "/" + command);
        if (password != null) {
            getMethod.setQueryString(new NameValuePair[] { new NameValuePair(PasswordProtectFilter.PASSWORD_PARAM_NAME,
                    password), });
        }

        try {
            httpClient.executeMethod(getMethod);
            String response = Strings.safeTrimOrNullString(getMethod.getResponseBodyAsString());
            if(response != null){
                System.out.println(response);
            }
        } catch (ConnectException e) {
            exit("Unable to connect to " + host + ":" + port + ", perhaps the service is not running", RC_CTX);
        } catch (IOException e) {
            exit("Error executing service command:\n" + e.getMessage(), RC_CTX);
        }

        int statusCode = getMethod.getStatusCode();
        if (statusCode == HttpStatus.SC_OK){
            return;
        }else if(statusCode == HttpStatus.SC_UNAUTHORIZED){
            exit("you are not authorized to execute admin commands; invalid password", RC_UNAUTHORIZED);
        }else{
            exit("Service returned unexpected HTTP status code; " + statusCode, RC_UNKNOWN);
        }
    }

    /**
     * Prints the given message to STDERR and exits with the given status code.
     * 
     * @param message the message to output, may be null if nothing is to be printed
     * @param returnCode the return code to be given for the application
     */
    private static void exit(String message, int returnCode) {
        if (message != null) {
            System.err.println(message);
        }
        System.exit(returnCode);
    }
}