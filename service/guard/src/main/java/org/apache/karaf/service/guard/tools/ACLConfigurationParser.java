package org.apache.karaf.service.guard.tools;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Dictionary;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;
import java.util.SortedMap;
import java.util.TreeMap;

import org.osgi.service.cm.Configuration;

// TODO this class is exactly the same as what is used in KarafMBeanServerGuard
public class ACLConfigurationParser {
    public static List<String> getRolesForInvocation(String methodName, Object[] params, Configuration config) {
        return getRolesForInvocation(methodName, params, null, config);
    }

    public static List<String> getRolesForInvocation(String methodName, Object[] params, String[] signature,
            Configuration config) {
        Dictionary<String, Object> properties = trimKeys(config.getProperties());

        /*
        1. get all direct string matches
        2. get regexp matches
        3. get signature matches
        4. get all direct string matches without signature
        5. get regexp matches without signature
        6. without signature
        7. method name wildcard

        We return immediately when a definition is found, so if a specific definition is found
        we do not search for a more generic specification.
        Regular expressions and exact matches are considered equally specific, so they are combined...
         */

        if (signature != null) {
            List<String> roles = getRolesBasedOnSignature(methodName, params, signature, properties);
            if (roles != null) {
                return roles;
            }
        }

        List<String> roles = getRolesBasedOnSignature(methodName, params, null, properties);
        if (roles != null) {
            return roles;
        }
        /*
        List<String> roles = new ArrayList<String>();
        Object methodRoles = properties.get(methodName);
        if (methodRoles instanceof String) {
            roles.addAll(parseRoles((String) methodRoles));
            return roles;
        }
        */

        return getMethodNameWildcardRoles(properties, methodName);
    }

    private static List<String> getRolesBasedOnSignature(String methodName, Object[] params, String[] signature,
            Dictionary<String, Object> properties) {
        List<String> roles = new ArrayList<String>();

        boolean foundExactOrRegExp = false;
        if (params != null) { // TODO can we get rid of this if? Is params ever not null?
            Object exactArgMatchRoles = properties.get(getExactArgSignature(methodName, signature, params));
            if (exactArgMatchRoles instanceof String) {
                roles.addAll(parseRoles((String) exactArgMatchRoles));
                foundExactOrRegExp = true;
            }

            foundExactOrRegExp |= getRegExpRoles(properties, methodName, signature, params, roles);

            if (foundExactOrRegExp) {
                // Since we have the actual parameters we can match them and if they do we won't look for any
                // more generic rules...
                return roles;
            }
        } else {
            foundExactOrRegExp = getExactArgOrRegExpRoles(properties, methodName, signature, roles);
        }

        Object signatureRoles = properties.get(getSignature(methodName, signature));
        if (signatureRoles instanceof String) {
            roles.addAll(parseRoles((String) signatureRoles));
            return roles;
        }

        if (foundExactOrRegExp) {
            // We can get here if params == null and there were exact and/or regexp rules but no signature rules
            return roles;
        }
        return null;
    }

    private static Dictionary<String, Object> trimKeys(Dictionary<String, Object> properties) {
        Dictionary<String, Object> d = new Hashtable<String, Object>();
        for (Enumeration<String> e = properties.keys(); e.hasMoreElements(); ) {
            String key = e.nextElement();
            Object value = properties.get(key);

            d.put(removeSpaces(key), value);
        }
        return d;
    }

    private static String removeSpaces(String key) {
        StringBuilder sb = new StringBuilder();
        char quoteChar = 0;
        for (int i = 0; i < key.length(); i++) {
            char c = key.charAt(i);

            if (quoteChar == 0 && c == ' ')
                continue;

            if (quoteChar == 0 && (c == '\"' || c == '/') && sb.length() > 0 &&
                    (sb.charAt(sb.length() - 1) == '[' || sb.charAt(sb.length() - 1) == ',')) {
                // we're in a quoted string
                quoteChar = c;
            } else if (quoteChar != 0 && c == quoteChar) {
                // look ahead to see if the next non-space is the closing bracket or a comma, which ends the quoted string
                for (int j = i + 1; j < key.length(); j++) {
                    if (key.charAt(j) == ' ') {
                        continue;
                    }
                    if (key.charAt(j) == ']' || key.charAt(j) == ',') {
                        quoteChar = 0;
                    }
                    break;
                }
            }

            sb.append(c);
        }

        return sb.toString();
    }

    public static List<String> parseRoles(String roleStr) {
        int hashIdx = roleStr.indexOf('#');
        if (hashIdx >= 0) {
            // You can put a comment at the end
            roleStr = roleStr.substring(0, hashIdx);
        }

        List<String> roles = new ArrayList<String>();
        for (String role : roleStr.split("[,]")) {
            String trimmed = role.trim();
            if (trimmed.length() > 0)
                roles.add(trimmed);
        }
        return roles;
    }

    private static Object getExactArgSignature(String methodName, String[] signature, Object[] params) {
        StringBuilder sb = new StringBuilder(getSignature(methodName, signature));
        sb.append('[');
        boolean first = true;
        for (Object param : params) {
            if (first)
                first = false;
            else
                sb.append(',');
            sb.append('"');
            sb.append(param.toString().trim());
            sb.append('"');
        }
        sb.append(']');
        return sb.toString();
    }

    private static String getSignature(String methodName, String[] signature) {
        StringBuilder sb = new StringBuilder(methodName);
        if (signature == null)
            return sb.toString();

        sb.append('(');
        boolean first = true;
        for (String s : signature) {
            if (first)
                first = false;
            else
                sb.append(',');

            sb.append(s);
        }
        sb.append(')');
        return sb.toString();
    }

    private static boolean getRegExpRoles(Dictionary<String, Object> properties, String methodName, String[] signature, Object[] params, List<String> roles) {
        boolean matchFound = false;
        String methodSig = getSignature(methodName, signature);
        String prefix = methodSig + "[/";
        for (Enumeration<String> e = properties.keys(); e.hasMoreElements(); ) {
            String key = e.nextElement().trim();
            if (key.startsWith(prefix) && key.endsWith("/]")) {
                List<String> regexpArgs = getRegExpDecl(key.substring(methodSig.length()));
                if (allParamsMatch(regexpArgs, params)) {
                    matchFound = true;
                    Object roleStr = properties.get(key);
                    if (roleStr instanceof String) {
                        // TODO can we not simply return here? There are other similar places too...
                        roles.addAll(parseRoles((String) roleStr));
                    }
                }
            }
        }
        return matchFound;
    }

    private static boolean getExactArgOrRegExpRoles(Dictionary<String, Object> properties, String methodName, String[] signature, List<String> roles) {
        boolean matchFound = false;
        String methodSig = getSignature(methodName, signature);
        String prefix = methodSig + "[";
        for (Enumeration<String> e = properties.keys(); e.hasMoreElements(); ) {
            String key = e.nextElement().trim();
            if (key.startsWith(prefix) && key.endsWith("]")) {
                matchFound = true;
                Object roleStr = properties.get(key);
                if (roleStr instanceof String) {
                    roles.addAll(parseRoles((String) roleStr));
                }
            }
        }
        return matchFound;
    }

    private static List<String> getMethodNameWildcardRoles(Dictionary<String, Object> properties, String methodName) {
        SortedMap<String, String> wildcardRules = new TreeMap<String, String>(new Comparator<String>() {
            public int compare(String s1, String s2) {
                // Returns longer entries before shorter ones...
                return s2.length() - s1.length();
            }
        });
        for (Enumeration<String> e = properties.keys(); e.hasMoreElements(); ) {
            String key = e.nextElement();
            if (key.endsWith("*")) {
                String prefix = key.substring(0, key.length() - 1);
                if (methodName.startsWith(prefix)) {
                    wildcardRules.put(prefix, properties.get(key).toString());
                }
            }
        }

        if (wildcardRules.size() != 0) {
            return parseRoles(wildcardRules.values().iterator().next());
        } else {
            return null;
        }
    }

    private static boolean allParamsMatch(List<String> regexpArgs, Object[] params) {
        if (regexpArgs.size() != params.length)
            return false;

        for (int i = 0; i < regexpArgs.size(); i++) {
            if (!params[i].toString().trim().matches(regexpArgs.get(i))) {
                return false;
            }
        }
        return true;
    }

    private static List<String> getRegExpDecl(String key) {
        List<String> l = new ArrayList<String>();

        boolean inRegExp = false;
        StringBuilder curRegExp = new StringBuilder();
        for (int i = 0; i < key.length(); i++) {
            if (!inRegExp) {
                if (key.length() > i+1) {
                    String s = key.substring(i, i+2);

                    if ("[/".equals(s) || ",/".equals(s)) {
                        inRegExp = true;
                        i++;
                        continue;
                    }
                }
            } else {
                String s = key.substring(i, i+2);
                if ("/]".equals(s) || "/,".equals(s)) {
                    l.add(curRegExp.toString());
                    curRegExp = new StringBuilder();
                    inRegExp = false;
                    continue;
                }
                curRegExp.append(key.charAt(i));
            }

        }
        return l;
    }
}
