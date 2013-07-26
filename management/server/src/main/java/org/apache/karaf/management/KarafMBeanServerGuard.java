/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.karaf.management;

import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Dictionary;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;
import java.util.SortedMap;
import java.util.TreeMap;

import javax.management.Attribute;
import javax.management.AttributeList;
import javax.management.JMException;
import javax.management.MBeanAttributeInfo;
import javax.management.MBeanInfo;
import javax.management.MBeanServer;
import javax.management.ObjectName;
import javax.security.auth.Subject;

import org.apache.karaf.jaas.boot.principal.RolePrincipal;
import org.apache.karaf.management.boot.KarafMBeanServerBuilder;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;

public final class KarafMBeanServerGuard implements InvocationHandler {
    private static final String JMX_ACL_PID_PREFIX = "jmx.acl";
    private ConfigurationAdmin configAdmin;

    public ConfigurationAdmin getConfigAdmin() {
        return configAdmin;
    }

    public void setConfigAdmin(ConfigurationAdmin configAdmin) {
        this.configAdmin = configAdmin;
    }

    public void init() {
        KarafMBeanServerBuilder.init(this);
    }

    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        if (method.getParameterTypes().length == 0)
            return null;

        if (!ObjectName.class.isAssignableFrom(method.getParameterTypes()[0]))
            return null;

        ObjectName objectName = (ObjectName) args[0];
        if ("getAttribute".equals(method.getName())) {
            handleGetAttribute(objectName, (String) args[1]);
        } else if ("getAttributes".equals(method.getName())) {
            handleGetAttributes(objectName, (String[]) args[1]);
        } else if ("setAttribute".equals(method.getName())) {
            handleSetAttribute((MBeanServer) proxy, objectName, (Attribute) args[1]);
        } else if ("setAttributes".equals(method.getName())) {
            handleSetAttributes((MBeanServer) proxy, objectName, (AttributeList) args[1]);
        } else if ("invoke".equals(method.getName())) {
            handleInvoke(objectName, (String) args[1], (Object[]) args[2], (String[]) args[3]);
        }

        return null;
    }

    private void handleGetAttribute(ObjectName objectName, String attributeName) throws IOException, InvalidSyntaxException {
        handleInvoke(objectName, "get" + attributeName, new Object [] {}, new String [] {});
    }

    private void handleGetAttributes(ObjectName objectName, String[] attributeNames) throws IOException, InvalidSyntaxException {
        for (String attr : attributeNames) {
            handleGetAttribute(objectName, attr);
        }
    }

    private void handleSetAttribute(MBeanServer proxy, ObjectName objectName, Attribute attribute) throws JMException, IOException, InvalidSyntaxException {
        String dataType = null;
        MBeanInfo info = proxy.getMBeanInfo(objectName);
        for (MBeanAttributeInfo attr : info.getAttributes()) {
            if (attr.getName().equals(attribute.getName())) {
                dataType = attr.getType();
                break;
            }
        }

        if (dataType == null)
            throw new IllegalStateException("Attribute data type could not be found");

        handleInvoke(objectName, "set" + attribute.getName(), new Object [] {attribute.getValue()}, new String [] {dataType});
    }

    private void handleSetAttributes(MBeanServer proxy, ObjectName objectName, AttributeList attributes) throws JMException, IOException, InvalidSyntaxException {
        for (Attribute attr : attributes.asList()) {
            handleSetAttribute(proxy, objectName, attr);
        }
    }

    void handleInvoke(ObjectName objectName, String operationName, Object[] params, String[] signature) throws IOException, InvalidSyntaxException {
        for (String role : getRequiredRoles(objectName, operationName, params, signature)) {
            if (currentUserHasRole(role)) {
                return;
            }
        }
        throw new SecurityException("Insufficient credentials for operation.");
    }

    List<String> getRequiredRoles(ObjectName objectName, String methodName, Object[] params, String[] signature) throws IOException, InvalidSyntaxException {
        List<String> roles = new ArrayList<String>();
        List<String> segs = getNameSegments(objectName);

        // TODO cache
        List<String> allPids = new ArrayList<String>();
        // TODO fine tune filter !?
        for (Configuration config : configAdmin.listConfigurations(null)) {
            allPids.add(config.getPid());
        }
        for (String pid : iterateDownPids(segs)) {
            if (allPids.contains(pid)) {
                Configuration config = configAdmin.getConfiguration(pid);
                Dictionary<String, Object> properties = trimKeys(config.getProperties());

                /*
                1. get all direct string matches
                2. get regexp matches
                3. get signature matches
                4. without signature
                5. method name wildcard

                We return immediately when a definition is found, so if a specific definition is found
                we do not search for a more generic specification.
                Regular expressions and exact matches are considered equally specific, so they are combined...
                 */

                boolean foundExactOrRegExp = false;
                Object exactArgMatchRoles = properties.get(getExactArgSignature(methodName, signature, params));
                if (exactArgMatchRoles instanceof String) {
                    roles.addAll(parseRoles((String) exactArgMatchRoles));
                    foundExactOrRegExp = true;
                }

                foundExactOrRegExp |= getRegExpRoles(properties, methodName, signature, params, roles);
                if (foundExactOrRegExp)
                    return roles;

                Object signatureRoles = properties.get(getSignature(methodName, signature));
                if (signatureRoles instanceof String) {
                    roles.addAll(parseRoles((String) signatureRoles));
                    return roles;
                }

                Object methodRoles = properties.get(methodName);
                if (methodRoles instanceof String) {
                    roles.addAll(parseRoles((String) methodRoles));
                    return roles;
                }

                if (getMethodNameWildcardRoles(properties, methodName, roles))
                    return roles;
            }
        }
        return roles;
    }

    private Dictionary<String, Object> trimKeys(Dictionary<String, Object> properties) {
        Dictionary<String, Object> d = new Hashtable<String, Object>();
        for (Enumeration<String> e = properties.keys(); e.hasMoreElements(); ) {
            String key = e.nextElement();
            Object value = properties.get(key);

            d.put(removeSpaces(key), value);
        }
        return d;
    }

    private String removeSpaces(String key) {
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

    private List<String> parseRoles(String roleStr) {
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

    private Object getExactArgSignature(String methodName, String[] signature, Object[] params) {
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

    private String getSignature(String methodName, String[] signature) {
        StringBuilder sb = new StringBuilder(methodName);
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

    private boolean getRegExpRoles(Dictionary<String, Object> properties, String methodName, String[] signature, Object[] params, List<String> roles) {
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
                        roles.addAll(parseRoles((String) roleStr));
                    }
                }
            }
        }
        return matchFound;
    }

    private boolean getMethodNameWildcardRoles(Dictionary<String, Object> properties, String methodName, List<String> roles) {
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
            roles.addAll(parseRoles(wildcardRules.values().iterator().next()));
            return true;
        } else {
            return false;
        }
    }

    private boolean allParamsMatch(List<String> regexpArgs, Object[] params) {
        if (regexpArgs.size() != params.length)
            return false;

        for (int i = 0; i < regexpArgs.size(); i++) {
            if (!params[i].toString().matches(regexpArgs.get(i))) {
                return false;
            }
        }
        return true;
    }

    private List<String> getRegExpDecl(String key) {
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

    private List<String> getNameSegments(ObjectName objectName) {
        List<String> segs = new ArrayList<String>();
        // segs.addAll(Arrays.asList(objectName.getDomain().split("[.]")));
        segs.add(objectName.getDomain());

        // TODO can an object name property contain a comma as key or value?
        // TODO support quoting as described in http://docs.oracle.com/javaee/1.4/api/javax/management/ObjectName.html
        for (String s : objectName.getKeyPropertyListString().split("[,]")) {
            int idx = s.indexOf('=');
            if (idx < 0)
                continue;

            segs.add(objectName.getKeyProperty(s.substring(0, idx)));
        }

        return segs;
    }

    /**
     * Given a list of segments return a list of pids that are searched in this order.
     * For example given the following segements: org.foo, bar, test
     * the following list of pids will be generated (in this order):
     *   jmx.acl.org.foo.bar.test
     *   jmx.acl.org.foo.bar
     *   jmx.acl.org.foo
     *   jmx.acl
     * The order is used as a search order, in which the most specific pid is searched first.
     * @param segs the segments
     * @return the pids in the above order.
     */
    private List<String> iterateDownPids(List<String> segs) {
        List<String> res = new ArrayList<String>();
        for (int i = segs.size(); i > 0; i--) {
            StringBuilder sb = new StringBuilder();
            sb.append(JMX_ACL_PID_PREFIX);
            for (int j = 0; j < i; j++) {
                sb.append('.');
                sb.append(segs.get(j));
            }
            res.add(sb.toString());
        }
        res.add(JMX_ACL_PID_PREFIX); // This is the topmost PID
        return res;
    }

    static boolean currentUserHasRole(String reqRole) {
        String clazz;
        String role;
        int idx = reqRole.indexOf(':');
        if (idx > 0) {
            clazz = reqRole.substring(0, idx);
            role = reqRole.substring(idx + 1);
        } else {
            clazz = RolePrincipal.class.getName();
            role = reqRole;
        }

        AccessControlContext acc = AccessController.getContext();
        if (acc == null)
            return false;
        Subject subject = Subject.getSubject(acc);
        if (subject == null)
            return false;

        for (Principal p : subject.getPrincipals()) {
            if (clazz.equals(p.getClass().getName()) && role.equals(p.getName())) {
                return true;
            }
        }
        return false;
    }
}
