package org.apache.karaf.management;

import java.io.ObjectInputStream;
import java.util.Arrays;
import java.util.Set;

import javax.management.Attribute;
import javax.management.AttributeList;
import javax.management.AttributeNotFoundException;
import javax.management.InstanceAlreadyExistsException;
import javax.management.InstanceNotFoundException;
import javax.management.IntrospectionException;
import javax.management.InvalidAttributeValueException;
import javax.management.ListenerNotFoundException;
import javax.management.MBeanException;
import javax.management.MBeanInfo;
import javax.management.MBeanRegistrationException;
import javax.management.MBeanServer;
import javax.management.NotCompliantMBeanException;
import javax.management.NotificationFilter;
import javax.management.NotificationListener;
import javax.management.ObjectInstance;
import javax.management.ObjectName;
import javax.management.OperationsException;
import javax.management.QueryExp;
import javax.management.ReflectionException;
import javax.management.loading.ClassLoaderRepository;

public class KarafMBeanServerWrapper implements MBeanServer {
    private final MBeanServer delegate;

    KarafMBeanServerWrapper(MBeanServer delegate) {
        this.delegate = delegate;
    }

    public ObjectInstance createMBean(String className, ObjectName name) throws ReflectionException,
            InstanceAlreadyExistsException, MBeanRegistrationException, MBeanException, NotCompliantMBeanException {
        return delegate.createMBean(className, name);
    }

    public ObjectInstance createMBean(String className, ObjectName name, ObjectName loaderName) throws ReflectionException,
            InstanceAlreadyExistsException, MBeanRegistrationException, MBeanException, NotCompliantMBeanException,
            InstanceNotFoundException {
        return delegate.createMBean(className, name, loaderName);
    }

    public ObjectInstance createMBean(String className, ObjectName name, Object[] params, String[] signature)
            throws ReflectionException, InstanceAlreadyExistsException, MBeanRegistrationException, MBeanException,
            NotCompliantMBeanException {
        return delegate.createMBean(className, name, params, signature);
    }

    public ObjectInstance createMBean(String className, ObjectName name, ObjectName loaderName, Object[] params,
            String[] signature) throws ReflectionException, InstanceAlreadyExistsException, MBeanRegistrationException,
            MBeanException, NotCompliantMBeanException, InstanceNotFoundException {
        return delegate.createMBean(className, name, loaderName, params, signature);
    }

    public ObjectInstance registerMBean(Object object, ObjectName name) throws InstanceAlreadyExistsException,
            MBeanRegistrationException, NotCompliantMBeanException {
        return delegate.registerMBean(object, name);
    }

    public void unregisterMBean(ObjectName name) throws InstanceNotFoundException, MBeanRegistrationException {
        delegate.unregisterMBean(name);
    }

    public ObjectInstance getObjectInstance(ObjectName name) throws InstanceNotFoundException {
        return delegate.getObjectInstance(name);
    }

    public Set<ObjectInstance> queryMBeans(ObjectName name, QueryExp query) {
        return delegate.queryMBeans(name, query);
    }

    public Set<ObjectName> queryNames(ObjectName name, QueryExp query) {
        return delegate.queryNames(name, query);
    }

    public boolean isRegistered(ObjectName name) {
        return delegate.isRegistered(name);
    }

    public Integer getMBeanCount() {
        return delegate.getMBeanCount();
    }

    public Object getAttribute(ObjectName name, String attribute) throws MBeanException, AttributeNotFoundException,
            InstanceNotFoundException, ReflectionException {
        if (attribute.equals("Framework")) {
            /* */ System.out.println("$$Obtaining attr: " + name + "#" + attribute);
            throw new SecurityException("Not allowed!");
        }
        return delegate.getAttribute(name, attribute);
    }

    public AttributeList getAttributes(ObjectName name, String[] attributes) throws InstanceNotFoundException,
            ReflectionException {

        if (Arrays.asList(attributes).contains("Framework")) {
            /* */ System.out.println("$$Obtaining attrs: " + name + "#" + Arrays.toString(attributes));
            throw new SecurityException("Not allowed!");
        }

        return delegate.getAttributes(name, attributes);
    }

    public void setAttribute(ObjectName name, Attribute attribute) throws InstanceNotFoundException, AttributeNotFoundException,
            InvalidAttributeValueException, MBeanException, ReflectionException {
        delegate.setAttribute(name, attribute);
    }

    public AttributeList setAttributes(ObjectName name, AttributeList attributes) throws InstanceNotFoundException,
            ReflectionException {
        return delegate.setAttributes(name, attributes);
    }

    public Object invoke(ObjectName name, String operationName, Object[] params, String[] signature)
            throws InstanceNotFoundException, MBeanException, ReflectionException {
        /* */ System.out.println("Invoking: " + name + "#" + operationName + "(" + Arrays.toString(params) + ")" + Arrays.toString(signature));
        return delegate.invoke(name, operationName, params, signature);
    }

    public String getDefaultDomain() {
        return delegate.getDefaultDomain();
    }

    public String[] getDomains() {
        return delegate.getDomains();
    }

    public void addNotificationListener(ObjectName name, NotificationListener listener, NotificationFilter filter, Object handback)
            throws InstanceNotFoundException {
        delegate.addNotificationListener(name, listener, filter, handback);
    }

    public void addNotificationListener(ObjectName name, ObjectName listener, NotificationFilter filter, Object handback)
            throws InstanceNotFoundException {
        delegate.addNotificationListener(name, listener, filter, handback);
    }

    public void removeNotificationListener(ObjectName name, ObjectName listener) throws InstanceNotFoundException,
            ListenerNotFoundException {
        delegate.removeNotificationListener(name, listener);
    }

    public void removeNotificationListener(ObjectName name, ObjectName listener, NotificationFilter filter, Object handback)
            throws InstanceNotFoundException, ListenerNotFoundException {
        delegate.removeNotificationListener(name, listener, filter, handback);
    }

    public void removeNotificationListener(ObjectName name, NotificationListener listener) throws InstanceNotFoundException,
            ListenerNotFoundException {
        delegate.removeNotificationListener(name, listener);
    }

    public void removeNotificationListener(ObjectName name, NotificationListener listener, NotificationFilter filter,
            Object handback) throws InstanceNotFoundException, ListenerNotFoundException {
        delegate.removeNotificationListener(name, listener, filter, handback);
    }

    public MBeanInfo getMBeanInfo(ObjectName name) throws InstanceNotFoundException, IntrospectionException, ReflectionException {
        return delegate.getMBeanInfo(name);
    }

    public boolean isInstanceOf(ObjectName name, String className) throws InstanceNotFoundException {
        return delegate.isInstanceOf(name, className);
    }

    public Object instantiate(String className) throws ReflectionException, MBeanException {
        return delegate.instantiate(className);
    }

    public Object instantiate(String className, ObjectName loaderName) throws ReflectionException, MBeanException,
            InstanceNotFoundException {
        return delegate.instantiate(className, loaderName);
    }

    public Object instantiate(String className, Object[] params, String[] signature) throws ReflectionException, MBeanException {
        return delegate.instantiate(className, params, signature);
    }

    public Object instantiate(String className, ObjectName loaderName, Object[] params, String[] signature)
            throws ReflectionException, MBeanException, InstanceNotFoundException {
        return delegate.instantiate(className, loaderName, params, signature);
    }

    public ObjectInputStream deserialize(ObjectName name, byte[] data) throws InstanceNotFoundException, OperationsException {
        return delegate.deserialize(name, data);
    }

    public ObjectInputStream deserialize(String className, byte[] data) throws OperationsException, ReflectionException {
        return delegate.deserialize(className, data);
    }

    public ObjectInputStream deserialize(String className, ObjectName loaderName, byte[] data) throws InstanceNotFoundException,
            OperationsException, ReflectionException {
        return delegate.deserialize(className, loaderName, data);
    }

    public ClassLoader getClassLoaderFor(ObjectName mbeanName) throws InstanceNotFoundException {
        return delegate.getClassLoaderFor(mbeanName);
    }

    public ClassLoader getClassLoader(ObjectName loaderName) throws InstanceNotFoundException {
        return delegate.getClassLoader(loaderName);
    }

    public ClassLoaderRepository getClassLoaderRepository() {
        return delegate.getClassLoaderRepository();
    }

}
