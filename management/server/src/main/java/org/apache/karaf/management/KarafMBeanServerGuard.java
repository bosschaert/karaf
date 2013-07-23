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
import java.util.Arrays;
import java.util.Dictionary;
import java.util.Enumeration;
import java.util.List;

import javax.management.Attribute;
import javax.management.AttributeList;
import javax.management.ObjectName;
import javax.security.auth.Subject;

import org.apache.karaf.jaas.boot.principal.RolePrincipal;
import org.apache.karaf.management.boot.KarafMBeanServerBuilder;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;

public final class KarafMBeanServerGuard implements InvocationHandler {
    private ConfigurationAdmin configAdmin;

    public ConfigurationAdmin getConfigAdmin() {
        return configAdmin;
    }

    public void setConfigAdmin(ConfigurationAdmin configAdmin) {
        this.configAdmin = configAdmin;
    }

    public void init() {
        System.out.println("**** Initializing guard...");
        KarafMBeanServerBuilder.init(this);
    }

    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        if (method.getParameterTypes().length == 0)
            return null;

        if (!ObjectName.class.isAssignableFrom(method.getParameterTypes()[0]))
            return null;

        // System.out.println("**** Guard being invoked:" + method.getName() + "#" + Arrays.toString(args));
        ObjectName objectName = (ObjectName) args[0];
        if (objectName.getCanonicalName().startsWith("org.apache.karaf")) {
            if ("getAttribute".equals(method.getName())) {
                handleGetAttribute(objectName, (String) args[1]);
            } else if ("getAttributes".equals(method.getName())) {
                handleGetAttributes(objectName, (String[]) args[1]);
            } else if ("setAttribute".equals(method.getName())) {
                handleSetAttribute(objectName, (Attribute) args[1]);
            } else if ("setAttributes".equals(method.getName())) {
                handleSetAttributes(objectName, (AttributeList) args[1]);
            } else if ("invoke".equals(method.getName())) {
                handleInvoke(objectName, (String) args[1], (Object[]) args[2], (String[]) args[3]);
            }

        }

        return null;
    }

    private void handleGetAttribute(ObjectName objectName, String attributeName) {
        // TODO Auto-generated method stub

    }

    private void handleGetAttributes(ObjectName objectName, String[] attributeNames) {
        // TODO Auto-generated method stub

    }

    private void handleSetAttribute(ObjectName objectName, Attribute attribute) {
        // TODO Auto-generated method stub

    }

    private void handleSetAttributes(ObjectName objectName, AttributeList attributes) {
        // TODO Auto-generated method stub

    }

    private void handleInvoke(ObjectName objectName, String operationName, Object[] params, String[] signature) throws IOException, InvalidSyntaxException {
        for (String role : getRequiredRoles(objectName, operationName, params, signature)) {
            if (currentUserHasRole(role)) {
                return;
            }
        }
        throw new SecurityException("Insufficient credentials for operation.");
    }

    private boolean currentUserHasRole(String reqRole) {
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

    private List<String> getRequiredRoles(ObjectName objectName, String methodName, Object[] params, String[] signature) throws IOException, InvalidSyntaxException {
        List<String> roles = new ArrayList<String>();
        List<String> segs = getNameSegments(objectName);

        // TODO cache
        List<String> allPids = new ArrayList<String>();
        // TODO fine tune filter !?
        for (Configuration config : configAdmin.listConfigurations(null)) {
            allPids.add(config.getPid());
        }
        for (String pid : iterateDownPids(segs)) {
            pid = "jmx.acl." + pid;
            if (allPids.contains(pid)) {
                Configuration config = configAdmin.getConfiguration(pid);

                /*
                1. get all direct string matches
                2. get regexp matches
                3. get signature matches
                4. without signature
                 */

                Object exactArgMatchRoles = config.getProperties().get(getExactArgSignature(methodName, signature, params));
                if (exactArgMatchRoles instanceof String) {
                    roles.addAll(parseRoles((String) exactArgMatchRoles));
                }

                List<String> regexpRoles = getRegExpRoles(config.getProperties(), methodName, signature, params);
                if (regexpRoles.size() > 0) {
                    roles.addAll(regexpRoles);
                }
                if (roles.size() > 0)
                    continue;

                Object signatureRoles = config.getProperties().get(getSignature(methodName, signature));
                if (signatureRoles instanceof String) {
                    roles.addAll(parseRoles((String) signatureRoles));
                    continue;
                }

                Object methodRoles = config.getProperties().get(methodName);
                if (methodRoles instanceof String) {
                    roles.addAll(parseRoles((String) methodRoles));
                }
            }
        }
        return roles;
    }

    private List<String> parseRoles(String roleStr) {
        return Arrays.asList(roleStr.split("[,]"));
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
            sb.append(param.toString());
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

    private List<String> getRegExpRoles(Dictionary<String, Object> properties, String methodName, String[] signature, Object[] params) {
        List<String> roles = new ArrayList<String>();
        String methodSig = getSignature(methodName, signature);
        String prefix = methodSig + "[/";
        for (Enumeration<String> e = properties.keys(); e.hasMoreElements(); ) {
            String key = e.nextElement().trim();
            if (key.startsWith(prefix) && key.endsWith("/]")) {
                List<String> regexpArgs = getRegExpDecl(key.substring(methodSig.length()));
                if (allParamsMatch(regexpArgs, params)) {
                    Object roleStr = properties.get(key);
                    if (roleStr instanceof String) {
                        roles.addAll(parseRoles((String) roleStr));
                    }
                }
            }
        }
        return roles;
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
                if ("[/".equals(key.substring(i, i+2))) {
                    inRegExp = true;
                    i++;
                    continue;
                }
            } else {
                if ("/]".equals(key.substring(i, i+2))) {
                    l.add(curRegExp.toString());
                    curRegExp = new StringBuilder();
                    inRegExp = false;
                    i++;
                    continue;
                }
                curRegExp.append(key.charAt(i));
            }

        }
        return l;
    }

    private List<String> getNameSegments(ObjectName objectName) {
        List<String> segs = new ArrayList<String>();
        segs.addAll(Arrays.asList(objectName.getDomain().split("[.]")));

        // TODO can an object name property contain a comma as key or value?
        for (String s : objectName.getKeyPropertyListString().split("[,]")) {
            int idx = s.indexOf('=');
            if (idx < 0)
                continue;

            segs.add(objectName.getKeyProperty(s.substring(0, idx)));
        }

        return segs;
    }

    private List<String> iterateDownPids(List<String> segs) {
        List<String> pids = new ArrayList<String>();
        for (int i = segs.size(); i > 0; i--) {
            StringBuilder sb = new StringBuilder();
            for (int j = 0; j < i; j++) {
                if (sb.length() > 0)
                    sb.append('.');
                sb.append(segs.get(j));
            }
            pids.add(sb.toString());
        }
        return pids;
    }
}
