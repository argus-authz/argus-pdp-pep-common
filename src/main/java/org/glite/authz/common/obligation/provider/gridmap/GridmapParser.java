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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.util.StringTokenizer;
import java.util.UnknownFormatConversionException;
import java.util.Vector;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.glite.authz.common.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** A parser of things nominally called gridmaps. */
public final class GridmapParser {

    /** Class logger. */
    private static final Logger LOG = LoggerFactory.getLogger(GridmapParser.class);

    /** Constructor. */
    private GridmapParser() {
    }

    /**
     * Parses a grid map file. The returned mapped and its contained lists are thread safe and fail-fast collections.
     * The key to the map is the DN while the value is the list of account names to which that DN maps.
     * 
     * @param gridMapReader the reader providing the grid map file
     * 
     * @return the parsed grid map
     * 
     * @throws IOException thrown if the reader faults
     */
    public static ConcurrentMap<FullyQualifiedName, Vector<String>> parse(Reader gridMapReader) throws IOException {
        BufferedReader bufferedReader = new BufferedReader(gridMapReader);
        ConcurrentHashMap<FullyQualifiedName, Vector<String>> gridMap = new ConcurrentHashMap<FullyQualifiedName, Vector<String>>();

        int lineNumber = 0;
        String line = bufferedReader.readLine();
        if (line != null) {
            do {
                lineNumber++;
                parseLine(gridMap, line, lineNumber);
                line = Strings.safeTrim(bufferedReader.readLine());
            } while (line != null);
        }

        return gridMap;
    }

    /**
     * Parses a single line in a grid map file.
     * 
     * @param gridMap the grid map to populate with the entry, if any, contained in this line
     * @param line the line to parse
     * @param lineNumber the current line number
     */
    private static void parseLine(ConcurrentHashMap<FullyQualifiedName, Vector<String>> gridMap, String line,
            int lineNumber) {
        if (Strings.isEmpty(line) || line.startsWith("#")) {
            // empty line or comment
            return;
        }

        if (line.charAt(0) != '\"') {
            LOG.error("Invalid gridmap entry on line {}. This line does not begin with a \"", lineNumber);
        }

        if (line.charAt(1) != '/') {
            LOG.error("Invalid gridmap entry on line {}. The entry does not begin with a /", lineNumber);
        }

        String name;
        String accounts;
        Pattern entryComponentPatter = Pattern.compile("^\"(/[a-zA-Z0-9=\\s\\\\/,.@()\"*_]+?)\"\\s(.*)$");
        Matcher matcher = entryComponentPatter.matcher(line);
        if (matcher.matches()) {
            name = Strings.safeTrim(matcher.group(1));
            accounts = matcher.group(2);

            if (gridMap.contains(name)) {
                LOG.error("gridmap file containes more than one entry for {}. The first duplicate is on line {}", name,
                        lineNumber);
            }

            Vector<String> accountNames = new Vector<String>();
            StringTokenizer tokens = new StringTokenizer(accounts, " ");
            String accountName;
            while (tokens.hasMoreElements()) {
                accountName = Strings.safeTrimOrNullString(tokens.nextToken());
                if (accountName != null) {
                    accountNames.add(Strings.safeTrim(unescapeString(accountName, lineNumber)));
                }
            }

            if (!isFQAN(name)) {
                gridMap.put(new DN(unescapeString(name, lineNumber)), accountNames);
            } else {
                gridMap.put(new FQAN(unescapeString(name, lineNumber)), accountNames);
            }

        }
    }

    /**
     * Checks if the given name is a FQAN.
     * 
     * @param name the name to check
     * 
     * @return true
     */
    private static boolean isFQAN(String name) {
        int firstIndex = name.indexOf('=');

        if (firstIndex == -1) {
            // All DNs must have at least one equals in them, FQANs need not
            return true;
        }

        // It's an FQAN if
        // - there is only one equal sign
        // - there is Role= that is proceeded by valid FQAN characters
        if (firstIndex == name.lastIndexOf('=')) {
            if (name.matches("^[a-zA-Z0-9._/*]*/Role=.*$")) {
                return true;
            }
        }

        return false;
    }

    /**
     * Unescapes a string. The standard Java escape sequences (b, f, n, r, t, u, \, ', ") are supported as well as \xXX
     * for hexadecimal character representation.
     * 
     * @param string the string to unescape
     * @param lineNumber the line number in which the string occurs
     * 
     * @return the unescaped string
     * 
     * @throws UnknownFormatConversionException thrown if an unsuported escape sequence is found
     */
    private static String unescapeString(String string, int lineNumber) throws UnknownFormatConversionException {
        char[] stringChars = string.toCharArray();
        StringBuilder unescapedString = new StringBuilder();
        char[] hexChars;

        for (int i = 0; i < stringChars.length; i++) {
            if (stringChars[i] != '\\') {
                unescapedString.append(stringChars[i]);
                continue;
            }

            switch (stringChars[i + 1]) {
                case 'b':
                    unescapedString.append('\b');
                    i++;
                    break;
                case 'f':
                    unescapedString.append('\f');
                    i++;
                    break;
                case 'n':
                    unescapedString.append('\n');
                    i++;
                    break;
                case 'r':
                    unescapedString.append('\r');
                    i++;
                    break;
                case 't':
                    unescapedString.append('\t');
                    i++;
                    break;
                case '\'':
                    unescapedString.append('\'');
                    i++;
                    break;
                case '"':
                    unescapedString.append('"');
                    i++;
                    break;
                case '\\':
                    unescapedString.append('\\');
                    i++;
                    break;
                case 'x':
                    hexChars = new char[2];
                    hexChars[0] = stringChars[i + 2];
                    hexChars[1] = stringChars[i + 3];
                    unescapedString.append((char) Integer.parseInt(new String(hexChars), 16));
                    i += 3;
                    break;
                case 'u':
                    hexChars = new char[4];
                    hexChars[0] = stringChars[i + 2];
                    hexChars[1] = stringChars[i + 3];
                    hexChars[2] = stringChars[i + 4];
                    hexChars[3] = stringChars[i + 5];
                    unescapedString.append((char) Integer.parseInt(new String(hexChars), 16));
                    i += 5;
                    break;
                default:
                    throw new UnknownFormatConversionException("Escape sequence '\\" + stringChars[i + 1] + "' (line: "
                            + lineNumber + ") is not supported");
            }
        }

        return unescapedString.toString().trim();
    }
}