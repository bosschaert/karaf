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
import java.security.Principal;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Dictionary;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.management.ObjectName;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import junit.framework.TestCase;

import org.apache.karaf.jaas.boot.principal.RolePrincipal;
import org.easymock.EasyMock;
import org.osgi.framework.Constants;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;

public class KarafMBeanServerGuardTest extends TestCase {
    public void testRequiredRolesMethodNameOnly() throws Exception {
        Dictionary<String, Object> configuration = new Hashtable<String, Object>();
        configuration.put("doit", "master");
        configuration.put("fryIt", "editor, viewer");
        ConfigurationAdmin ca = getMockConfigAdmin(configuration);

        KarafMBeanServerGuard guard = new KarafMBeanServerGuard();
        guard.setConfigAdmin(ca);

        ObjectName on = ObjectName.getInstance("foo.bar:type=Test");
        assertEquals(Collections.singletonList("master"),
                guard.getRequiredRoles(on, "doit", new Object[] {}, new String [] {}));
        assertEquals(Arrays.asList("editor", "viewer"),
                guard.getRequiredRoles(on, "fryIt", new Object[] {"blah"}, new String [] {"java.lang.String"}));
    }

    public void testRequiredRolesSignature() throws Exception {
        Dictionary<String, Object> configuration = new Hashtable<String, Object>();
        configuration.put("testIt", "master");
        configuration.put("testIt( java.lang.String)", "viewer");
        configuration.put("testIt( java.lang.String ,java.lang.String)", "editor");
        ConfigurationAdmin ca = getMockConfigAdmin(configuration);

        KarafMBeanServerGuard guard = new KarafMBeanServerGuard();
        guard.setConfigAdmin(ca);

        ObjectName on = ObjectName.getInstance("foo.bar:type=Test");
        assertEquals(Collections.singletonList("editor"),
                guard.getRequiredRoles(on, "testIt", new Object[] {"test", "toast"}, new String [] {"java.lang.String", "java.lang.String"}));
    }

    public void testRequiredRolesExact() throws Exception {
        Dictionary<String, Object> configuration = new Hashtable<String, Object>();
        configuration.put("testIt", "master");
        configuration.put("testIt( java.lang.String)", "viewer");
        configuration.put("testIt( java.lang.String ,java.lang.String)", "editor");
        configuration.put("testIt( java.lang.String ) [\"ab\"]", "manager");
        configuration.put("testIt( java.lang.String )[\" a b \" ]", "admin");
        configuration.put("testIt( java.lang.String )[ \" cd \"]  ", "tester");
        configuration.put("testIt(java.lang.String)[\"cd/\"]", "monkey");
        configuration.put("testIt(java.lang.String)[\"cd\"\"]", "donkey");
        ConfigurationAdmin ca = getMockConfigAdmin(configuration);

        KarafMBeanServerGuard guard = new KarafMBeanServerGuard();
        guard.setConfigAdmin(ca);

        ObjectName on = ObjectName.getInstance("foo.bar:type=Test");
        assertEquals(Collections.singletonList("manager"),
                guard.getRequiredRoles(on, "testIt", new Object[] {"ab"}, new String [] {"java.lang.String"}));
        assertEquals(Collections.singletonList("admin"),
                guard.getRequiredRoles(on, "testIt", new Object[] {" a b "}, new String [] {"java.lang.String"}));
        assertEquals("Doesn't match the exact, space mismatch",
                Collections.singletonList("viewer"),
                guard.getRequiredRoles(on, "testIt", new Object[] {"cd"}, new String [] {"java.lang.String"}));
        assertEquals(Collections.singletonList("monkey"),
                guard.getRequiredRoles(on, "testIt", new Object[] {"cd/"}, new String [] {"java.lang.String"}));
        assertEquals(Collections.singletonList("donkey"),
                guard.getRequiredRoles(on, "testIt", new Object[] {"cd\""}, new String [] {"java.lang.String"}));
    }

    public void testRequiredRolesExact2() throws Exception {
        Dictionary<String, Object> configuration = new Hashtable<String, Object>();
        configuration.put("foo(java.lang.String,java.lang.String)[\"a\",\",\"]", "editor");
        configuration.put("foo(java.lang.String,java.lang.String)[\",\" , \"a\"]", "viewer");
        ConfigurationAdmin ca = getMockConfigAdmin(configuration);

        KarafMBeanServerGuard guard = new KarafMBeanServerGuard();
        guard.setConfigAdmin(ca);

        ObjectName on = ObjectName.getInstance("foo.bar:type=Test");
        assertEquals(Collections.singletonList("editor"),
                guard.getRequiredRoles(on, "foo", new Object[] {"a", ","}, new String [] {"java.lang.String", "java.lang.String"}));
        assertEquals(Collections.singletonList("viewer"),
                guard.getRequiredRoles(on, "foo", new Object[] {",", "a"}, new String [] {"java.lang.String", "java.lang.String"}));
        assertEquals(Collections.emptyList(),
                guard.getRequiredRoles(on, "foo", new Object[] {"a", "a"}, new String [] {"java.lang.String", "java.lang.String"}));
    }

    public void testRequiredRolesRegExp() throws Exception {
        Dictionary<String, Object> configuration = new Hashtable<String, Object>();
        configuration.put("  testIt   (java.lang.String)  [  /ab/]", "manager");
        configuration.put("testIt(java.lang.String)[/ c\"d /]", "tester");
        ConfigurationAdmin ca = getMockConfigAdmin(configuration);

        KarafMBeanServerGuard guard = new KarafMBeanServerGuard();
        guard.setConfigAdmin(ca);

        ObjectName on = ObjectName.getInstance("foo.bar:type=Test");
        assertEquals(Collections.singletonList("manager"),
                guard.getRequiredRoles(on, "testIt", new Object[] {"ab"}, new String [] {"java.lang.String"}));
        assertEquals(Collections.emptyList(),
                guard.getRequiredRoles(on, "testIt", new Object[] {" a b "}, new String [] {"java.lang.String"}));
        assertEquals(Collections.singletonList("tester"),
                guard.getRequiredRoles(on, "testIt", new Object[] {" c\"d "}, new String [] {"java.lang.String"}));

    }

    public void testRequiredRolesRegExp2() throws Exception {
        Dictionary<String, Object> configuration = new Hashtable<String, Object>();
        configuration.put("foo(java.lang.String,java.lang.String)[/a/,/b/]", "editor");
        configuration.put("foo(java.lang.String,java.lang.String)[/[bc]/ , /[^b]/]", "viewer");
        ConfigurationAdmin ca = getMockConfigAdmin(configuration);

        KarafMBeanServerGuard guard = new KarafMBeanServerGuard();
        guard.setConfigAdmin(ca);

        ObjectName on = ObjectName.getInstance("foo.bar:type=Test");
        assertEquals(Collections.singletonList("editor"),
                guard.getRequiredRoles(on, "foo", new Object[] {"a", "b"}, new String [] {"java.lang.String", "java.lang.String"}));
        assertEquals(Collections.singletonList("viewer"),
                guard.getRequiredRoles(on, "foo", new Object[] {"b", "a"}, new String [] {"java.lang.String", "java.lang.String"}));
        assertEquals(Collections.singletonList("viewer"),
                guard.getRequiredRoles(on, "foo", new Object[] {"c", "c"}, new String [] {"java.lang.String", "java.lang.String"}));
        assertEquals(Collections.emptyList(),
                guard.getRequiredRoles(on, "foo", new Object[] {"b", "b"}, new String [] {"java.lang.String", "java.lang.String"}));
    }

    @SuppressWarnings("unchecked")
    public void testRequiredRolesHierarchy() throws Exception {
        Dictionary<String, Object> conf1 = new Hashtable<String, Object>();
        conf1.put("foo", "editor");
        conf1.put(Constants.SERVICE_PID, "jmx.acl.foo.bar.Test");
        Dictionary<String, Object> conf2 = new Hashtable<String, Object>();
        conf2.put("bar", "viewer");
        conf2.put("foo", "viewer");
        conf2.put(Constants.SERVICE_PID, "jmx.acl.foo.bar");
        Dictionary<String, Object> conf3 = new Hashtable<String, Object>();
        conf3.put("tar", "admin");
        conf3.put(Constants.SERVICE_PID, "jmx.acl.foo");
        Dictionary<String, Object> conf4 = new Hashtable<String, Object>();
        conf4.put("zar", "visitor");
        conf4.put(Constants.SERVICE_PID, "jmx.acl");

        ConfigurationAdmin ca = getMockConfigAdmin2(conf1, conf2, conf3, conf4);
        assertEquals("Precondition", 4, ca.listConfigurations(null).length);

        KarafMBeanServerGuard guard = new KarafMBeanServerGuard();
        guard.setConfigAdmin(ca);

        ObjectName on = ObjectName.getInstance("foo.bar:type=Test");
        assertEquals("Should only return the most specific definition",
                Collections.singletonList("editor"),
                guard.getRequiredRoles(on, "foo", new Object[] {}, new String [] {}));
        assertEquals(Collections.singletonList("viewer"),
                guard.getRequiredRoles(on, "bar", new Object[] {"test"}, new String [] {"java.lang.String"}));
        assertEquals("The top-level is the domain, subsections of the domain should not be searched",
                Collections.emptyList(),
                guard.getRequiredRoles(on, "tar", new Object[] {}, new String [] {}));
        assertEquals("The top-level is the domain, subsections of the domain should not be searched",
                Collections.emptyList(),
                guard.getRequiredRoles(on, "zar", new Object[] {}, new String [] {}));
    }

    public void testRequiredRolesMethodNameWildcard() throws Exception {
        Dictionary<String, Object> configuration = new Hashtable<String, Object>();
        configuration.put("getFoo", "viewer");
        configuration.put("get*", " tester , editor,manager");
        configuration.put("*", "admin");
        ConfigurationAdmin ca = getMockConfigAdmin(configuration);

        KarafMBeanServerGuard guard = new KarafMBeanServerGuard();
        guard.setConfigAdmin(ca);

        ObjectName on = ObjectName.getInstance("foo.bar:type=Test");
        assertEquals(Collections.singletonList("viewer"),
                guard.getRequiredRoles(on, "getFoo", new Object[] {}, new String [] {}));
        assertEquals(Arrays.asList("tester", "editor", "manager"),
                guard.getRequiredRoles(on, "getBar", new Object[] {}, new String [] {}));
        assertEquals(Collections.singletonList("admin"),
                guard.getRequiredRoles(on, "test", new Object[] {new Long(17)}, new String [] {"java.lang.Long"}));
    }

    @SuppressWarnings("unchecked")
    private ConfigurationAdmin getMockConfigAdmin(Dictionary<String, Object> configuration) throws IOException,
            InvalidSyntaxException {
        configuration.put(Constants.SERVICE_PID, "jmx.acl.foo.bar.Test");
        return getMockConfigAdmin2(configuration);
    }

    private ConfigurationAdmin getMockConfigAdmin2(Dictionary<String, Object> ... configurations) throws IOException,
        InvalidSyntaxException {
        List<Configuration> allConfigs = new ArrayList<Configuration>();
        for (Dictionary<String, Object> configuration : configurations) {
            Configuration conf = EasyMock.createMock(Configuration.class);
            EasyMock.expect(conf.getPid()).andReturn((String) configuration.get(Constants.SERVICE_PID)).anyTimes();
            EasyMock.expect(conf.getProperties()).andReturn(configuration).anyTimes();
            EasyMock.replay(conf);
            allConfigs.add(conf);
        }

        ConfigurationAdmin ca = EasyMock.createMock(ConfigurationAdmin.class);
        for (Configuration c : allConfigs) {
            EasyMock.expect(ca.getConfiguration(c.getPid())).andReturn(c).anyTimes();
        }
        EasyMock.expect(ca.listConfigurations((String) EasyMock.anyObject())).andReturn(
                allConfigs.toArray(new Configuration [] {})).anyTimes();
        EasyMock.replay(ca);
        return ca;
    }

    public void testCurrentUserHasRole() throws Exception {
        Subject subject = new Subject();
        LoginModule lm = new TestLoginModule("test");
        lm.initialize(subject, null, null, null);
        lm.login();
        lm.commit();

        Subject.doAs(subject, new PrivilegedAction<String>() {
            public String run() {
                assertTrue(KarafMBeanServerGuard.currentUserHasRole("test"));
                assertFalse(KarafMBeanServerGuard.currentUserHasRole("toast"));
                return null;
            }
        });
    }

    public void testCurrentUserHasCustomRole() throws Exception {
        Subject subject = new Subject();
        LoginModule lm = new TestLoginModule(new TestRolePrincipal("foo"));
        lm.initialize(subject, null, null, null);
        lm.login();
        lm.commit();

        Subject.doAs(subject, new PrivilegedAction<String>() {
            public String run() {
                assertTrue(KarafMBeanServerGuard.currentUserHasRole(TestRolePrincipal.class.getCanonicalName() + ":foo"));
                assertFalse(KarafMBeanServerGuard.currentUserHasRole("foo"));
                return null;
            }
        });
    }

    /*
    public void xxtestKarafMBeanServerGuard() throws Exception {
        ConfigurationAdmin ca = EasyMock.createMock(ConfigurationAdmin.class);

        KarafMBeanServerGuard guard = new KarafMBeanServerGuard();
        guard.setConfigAdmin(ca);

        ObjectName on = ObjectName.getInstance("foo.bar:type=Test");
        guard.handleInvoke(on, "doit", new Object[] {}, new String [] {});
    }
    */
    private static class TestLoginModule implements LoginModule {
        private final Principal [] principals;
        private Subject subject;

        private static Principal [] getPrincipals(String... roles) {
            List<Principal> principals = new ArrayList<Principal>();
            for (String role : roles) {
                principals.add(new RolePrincipal(role));
            }
            return principals.toArray(new Principal [] {});
        }


        public TestLoginModule(String ... roles) {
            this(getPrincipals(roles));
        }

        public TestLoginModule(Principal ... principals) {
            this.principals = principals;
        }

        public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
            this.subject = subject;
        }

        public boolean login() throws LoginException {
            return true;
        }

        public boolean commit() throws LoginException {
            Set<Principal> sp = subject.getPrincipals();
            sp.addAll(Arrays.asList(principals));
            return true;
        }

        public boolean abort() throws LoginException {
            return true;
        }

        public boolean logout() throws LoginException {
            Set<Principal> sp = subject.getPrincipals();
            sp.removeAll(Arrays.asList(principals));
            return true;
        }
    }

}
