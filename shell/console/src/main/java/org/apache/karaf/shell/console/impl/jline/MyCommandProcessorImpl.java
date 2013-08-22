package org.apache.karaf.shell.console.impl.jline;

import java.security.AccessControlContext;
import java.security.AccessController;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.security.auth.Subject;

import org.apache.felix.gogo.api.CommandSessionListener;
import org.apache.felix.gogo.runtime.CommandProcessorImpl;
import org.apache.felix.gogo.runtime.CommandProxy;
import org.apache.felix.gogo.runtime.activator.Activator;
import org.apache.felix.service.command.CommandProcessor;
import org.apache.felix.service.command.Converter;
import org.apache.felix.service.command.Function;
import org.apache.felix.service.threadio.ThreadIO;
import org.apache.karaf.jaas.boot.principal.RolePrincipal;
import org.apache.karaf.shell.security.impl.CommandProxyCatalog;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Filter;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.framework.ServiceReference;
import org.osgi.util.tracker.ServiceTracker;

public class MyCommandProcessorImpl extends CommandProcessorImpl {
    private final BundleContext bundleContext;
    private final ServiceReference<ThreadIO> threadIOServiceReference;
    private final String roleClause;
    private final ServiceTracker commandTracker;
    private final ServiceTracker converterTracker;
    private final ServiceTracker listenerTracker;

    MyCommandProcessorImpl(BundleContext bc) {
        this(bc, bc.getServiceReference(ThreadIO.class));
    }

    private MyCommandProcessorImpl(BundleContext bc, ServiceReference<ThreadIO> sr) {
        super(bc.getService(sr));
        bundleContext = bc;
        threadIOServiceReference = sr;

        AccessControlContext acc = AccessController.getContext();
        Subject sub = Subject.getSubject(acc);
        System.out.println("!!! Subject: " + sub);

        Set<RolePrincipal> rolePrincipals = sub.getPrincipals(RolePrincipal.class);
        if (rolePrincipals.size() == 0)
            throw new IllegalStateException("Current user has no associated roles.");

        // TODO cater for custom roles
        // TODO is this search clause the most efficient way to find the appropriate commands?
        StringBuilder sb = new StringBuilder();
        sb.append("(|");
        for (RolePrincipal rp : rolePrincipals) {
            sb.append('(');
            sb.append(CommandProxyCatalog.PROXY_COMMAND_ROLES_PROPERTY);
            sb.append('=');
            sb.append(rp.getName());
            sb.append(')');
        }
        sb.append(')');
        roleClause = sb.toString();

        addConstant(Activator.CONTEXT, bc);
        addCommand("osgi", this, "addCommand");
        addCommand("osgi", this, "removeCommand");
        addCommand("osgi", this, "eval");

        try {
            commandTracker = trackCommands(bc);
            commandTracker.open();
            converterTracker = trackConverters(bc);
            converterTracker.open();
            listenerTracker = trackListeners(bc);
            listenerTracker.open();
        } catch (InvalidSyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    void close() {
        commandTracker.close();
        converterTracker.close();
        listenerTracker.close();
        bundleContext.ungetService(threadIOServiceReference);
        System.out.println("*** Closed MyCommandProcessor");
    }

    private ServiceTracker trackCommands(final BundleContext context) throws InvalidSyntaxException
    {
        Filter filter = context.createFilter(String.format("(&(%s=*)(%s=*)%s)",
            CommandProcessor.COMMAND_SCOPE, CommandProcessor.COMMAND_FUNCTION, roleClause));
//        Filter filter = context.createFilter(String.format("(&(!(%s=*))(%s=*))",
//                CommandProcessor.COMMAND_SCOPE, CommandProcessor.COMMAND_FUNCTION));

        return new ServiceTracker(context, filter, null)
        {
            @Override
            public Object addingService(ServiceReference reference)
            {
                Object scope = reference.getProperty(CommandProcessor.COMMAND_SCOPE);
                Object function = reference.getProperty(CommandProcessor.COMMAND_FUNCTION);
                List<Object> commands = new ArrayList<Object>();

                if (scope != null && function != null)
                {
                    if (function.getClass().isArray())
                    {
                        for (Object f : ((Object[]) function))
                        {
                            Function target = new CommandProxy(context, reference,
                                f.toString());
                            addCommand(scope.toString(), target, f.toString());
                            commands.add(target);
                        }
                    }
                    else
                    {
                        Function target = new CommandProxy(context, reference,
                            function.toString());
                        addCommand(scope.toString(), target, function.toString());
                        commands.add(target);
                    }
                    return commands;
                }
                return null;
            }

            @Override
            public void removedService(ServiceReference reference, Object service)
            {
                Object scope = reference.getProperty(CommandProcessor.COMMAND_SCOPE);
                Object function = reference.getProperty(CommandProcessor.COMMAND_FUNCTION);

                if (scope != null && function != null)
                {
                    if (!function.getClass().isArray())
                    {
                        removeCommand(scope.toString(), function.toString());
                    }
                    else
                    {
                        for (Object func : (Object[]) function)
                        {
                            removeCommand(scope.toString(), func.toString());
                        }
                    }
                }

                super.removedService(reference, service);
            }
        };
    }

    private ServiceTracker trackConverters(BundleContext context) {
        return new ServiceTracker(context, Converter.class.getName(), null)
        {
            @Override
            public Object addingService(ServiceReference reference)
            {
                Converter converter = (Converter) super.addingService(reference);
                addConverter(converter);
                return converter;
            }

            @Override
            public void removedService(ServiceReference reference, Object service)
            {
                removeConverter((Converter) service);
                super.removedService(reference, service);
            }
        };
    }

    private ServiceTracker trackListeners(BundleContext context) {
        return new ServiceTracker(context, CommandSessionListener.class.getName(), null)
        {
            @Override
            public Object addingService(ServiceReference reference) {
                CommandSessionListener listener = (CommandSessionListener) super.addingService(reference);
                addListener(listener);
                return listener;
            }

            @Override
            public void removedService(ServiceReference reference, Object service) {
                removeListener((CommandSessionListener) service);
                super.removedService(reference, service);
            }
        };
    }
}
