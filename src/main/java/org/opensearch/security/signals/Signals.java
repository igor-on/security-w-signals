package org.opensearch.security.signals;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.lifecycle.AbstractLifecycleComponent;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.set.Sets;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.script.ScriptService;
import org.opensearch.security.internalauthtoken.InternalAuthTokenProvider;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.watcher.ResourceWatcherService;

import org.opensearch.security.codova.validation.ConfigValidationException;
import org.opensearch.security.configuration.ProtectedConfigIndexService;
import org.opensearch.security.configuration.ProtectedConfigIndexService.ConfigIndex;
import org.opensearch.security.configuration.ProtectedConfigIndexService.FailureListener;
import org.opensearch.security.modules.state.ComponentState;
import org.opensearch.security.modules.state.ComponentState.State;
import org.opensearch.security.securityconf.ConfigModel;
import org.opensearch.security.securityconf.DynamicConfigFactory;
import org.opensearch.security.securityconf.DynamicConfigFactory.DCFListener;
import org.opensearch.security.securityconf.DynamicConfigModel;
import org.opensearch.security.securityconf.InternalUsersModel;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.security.searchsupport.diag.DiagnosticContext;
import org.opensearch.security.signals.accounts.AccountRegistry;
import org.opensearch.security.signals.settings.SignalsSettings;
import org.opensearch.security.signals.settings.SignalsSettings.StaticSettings.IndexNames;
import org.opensearch.security.signals.watch.Watch;
import org.opensearch.security.signals.watch.state.WatchState;
import com.google.common.io.BaseEncoding;

public class Signals extends AbstractLifecycleComponent {
    private static final Logger log = LogManager.getLogger(Signals.class);

    private final ComponentState componentState;
    private final SignalsSettings signalsSettings;
    private NodeEnvironment nodeEnvironment;

    private final Map<String, SignalsTenant> tenants = new ConcurrentHashMap<>();
    private Set<String> configuredTenants;
    private Client client;
    private ClusterService clusterService;
    private NamedXContentRegistry xContentRegistry;
    private ScriptService scriptService;
    private InternalAuthTokenProvider internalAuthTokenProvider;
    private AccountRegistry accountRegistry;
    private InitializationState initState = InitializationState.INITIALIZING;
    private Exception initException;
    private Settings settings;
    private String nodeId;
    private Map<String, Exception> tenantInitErrors = new ConcurrentHashMap<>();
    private  DiagnosticContext diagnosticContext;

    public Signals(Settings settings, ComponentState componentState) {
        this.componentState = componentState;
        this.settings = settings;
        this.signalsSettings = new SignalsSettings(settings);
        this.signalsSettings.addChangeListener(this.settingsChangeListener);
    }

    public Collection<Object> createComponents(Client client, ClusterService clusterService, ThreadPool threadPool,
            ResourceWatcherService resourceWatcherService, ScriptService scriptService, NamedXContentRegistry xContentRegistry,
            Environment environment, NodeEnvironment nodeEnvironment, InternalAuthTokenProvider internalAuthTokenProvider,
            ProtectedConfigIndexService protectedConfigIndexService, DynamicConfigFactory dynamicConfigFactory, DiagnosticContext diagnosticContext) {

        try {
            nodeId = nodeEnvironment.nodeId();

            if (!signalsSettings.getStaticSettings().isEnabled()) {
                initState = InitializationState.DISABLED;
                return Collections.emptyList();
            }

            this.client = client;
            this.clusterService = clusterService;
            this.nodeEnvironment = nodeEnvironment;
            this.xContentRegistry = xContentRegistry;
            this.scriptService = scriptService;
            this.internalAuthTokenProvider = internalAuthTokenProvider;
            this.diagnosticContext = diagnosticContext;

            createIndexes(protectedConfigIndexService);

            // TODO: IGOR_ON CHANGE (always init enterprise modules)
//            if (settings.getAsBoolean(ConfigConstants.SEARCHGUARD_ENTERPRISE_MODULES_ENABLED, true)
//                    && signalsSettings.getStaticSettings().isEnterpriseEnabled()) {
//            }

            initEnterpriseModules();

            this.accountRegistry = new AccountRegistry(signalsSettings);

            dynamicConfigFactory.registerDCFListener(dcfListener);

            return Collections.singletonList(this);

        } catch (Exception e) {
            initState = InitializationState.FAILED;
            initException = e;
            log.error("Error while initializing Signals", e);
            throw e instanceof RuntimeException ? (RuntimeException) e : new RuntimeException(e);
        }
    }

    public SignalsTenant getTenant(User user) throws SignalsUnavailableException, NoSuchTenantException {
        if (user == null) {
            throw new IllegalArgumentException("No user specified");
        } else {
            return getTenant(user.getRequestedTenant());
        }
    }

    public SignalsTenant getTenant(String name) throws SignalsUnavailableException, NoSuchTenantException {
        checkInitState();

        if (name == null || name.length() == 0 || "_main".equals(name) || "SGS_GLOBAL_TENANT".equals(name)) {
            name = "_main";
        }

        SignalsTenant result = this.tenants.get(name);

        if (result != null) {
            return result;
        } else {
            Exception tenantInitError = tenantInitErrors.get(name);

            if (tenantInitError != null) {
                throw new SignalsUnavailableException("Tenant " + name + " failed to intialize", nodeId, null, tenantInitError);
            } else {
                throw new NoSuchTenantException(name);
            }
        }
    }

    private void createIndexes(ProtectedConfigIndexService protectedConfigIndexService) {

        IndexNames indexNames = signalsSettings.getStaticSettings().getIndexNames();

        String[] allIndexes = new String[] { indexNames.getWatches(), indexNames.getWatchesState(), indexNames.getWatchesTriggerState(),
                indexNames.getAccounts(), indexNames.getSettings() };

        componentState.addPart(protectedConfigIndexService.createIndex(
                new ConfigIndex(indexNames.getWatches()).mapping(Watch.getIndexMapping()).dependsOnIndices(allIndexes).onIndexReady(this::init)));
        componentState.addPart(
                protectedConfigIndexService.createIndex(new ConfigIndex(indexNames.getWatchesState()).mapping(WatchState.getIndexMapping())));
        componentState.addPart(protectedConfigIndexService.createIndex(new ConfigIndex(indexNames.getWatchesTriggerState())));
        componentState.addPart(protectedConfigIndexService.createIndex(new ConfigIndex(indexNames.getAccounts())));
        componentState.addPart(protectedConfigIndexService.createIndex(new ConfigIndex(indexNames.getSettings())));
    }

    private void checkInitState() throws SignalsUnavailableException {
        switch (initState) {
        case INITIALIZED:
            return;
        case DISABLED:
            throw new SignalsUnavailableException("Signals is disabled", nodeId, initState);
        case INITIALIZING:
            if (initException != null) {
                throw new SignalsUnavailableException(
                        "Signals encountered errors while initializing but is still trying to start up. Please try again later.", nodeId, initState,
                        initException);
            } else {
                throw new SignalsUnavailableException("Signals is still initializing. Please try again later.", nodeId, initState);
            }
        case FAILED:
            throw new SignalsUnavailableException("Signals failed to initialize on node " + nodeId + ". Please contact admin or check the ES logs.",
                    nodeId, initState, initException);
        }
    }

    private void createTenant(String name) {
        if ("SGS_GLOBAL_TENANT".equals(name)) {
            name = "_main";
        }

        ComponentState tenantState = componentState.getOrCreatePart("tenant", name);
        tenantState.setMandatory(false);

        try {

            SignalsTenant signalsTenant = SignalsTenant.create(name, client, clusterService, nodeEnvironment, scriptService, xContentRegistry,
                    internalAuthTokenProvider, signalsSettings, accountRegistry, tenantState, diagnosticContext);

            tenants.put(name, signalsTenant);

            log.debug("Tenant {} created", name);
        } catch (Exception e) {
            log.error("Error while creating tenant " + name, e);
            tenantInitErrors.put(name, e);
            tenantState.setFailed(e);
        }
    }

    private void deleteTenant(String name) throws SignalsUnavailableException, NoSuchTenantException {
        SignalsTenant tenant = getTenant(name);
        if (tenant != null) {
            tenant.delete();
            tenants.remove(name);
            log.debug("Tenant {} deleted", name);
        } else {
            log.debug("Trying to delete non-existing tenant {}", name);
        }
    }

    private synchronized void init(FailureListener failureListener) {
        if (initState == InitializationState.INITIALIZED) {
            return;
        }

        try {
            log.info("Initializing Signals");

            componentState.setState(State.INITIALIZING, "reading_settings");
            signalsSettings.refresh(client);

            componentState.setState(State.INITIALIZING, "reading_accounts");
            accountRegistry.init(client);

            componentState.setState(State.INITIALIZING, "initializing_keys");
            if (signalsSettings.getDynamicSettings().getInternalAuthTokenSigningKey() != null) {
                internalAuthTokenProvider.setSigningKey(signalsSettings.getDynamicSettings().getInternalAuthTokenSigningKey());
            }

            if (signalsSettings.getDynamicSettings().getInternalAuthTokenEncryptionKey() != null) {
                internalAuthTokenProvider.setEncryptionKey(signalsSettings.getDynamicSettings().getInternalAuthTokenEncryptionKey());
            }

            if ((signalsSettings.getDynamicSettings().getInternalAuthTokenSigningKey() == null
                    || signalsSettings.getDynamicSettings().getInternalAuthTokenEncryptionKey() == null)
                    && clusterService.state().nodes().isLocalNodeElectedMaster()) {
                log.info("Generating keys for internal auth token");

                String signingKey = signalsSettings.getDynamicSettings().getInternalAuthTokenSigningKey();
                String encryptionKey = signalsSettings.getDynamicSettings().getInternalAuthTokenEncryptionKey();

                if (signingKey == null) {
                    signingKey = generateKey(512);
                }

                if (encryptionKey == null) {
                    encryptionKey = generateKey(256);
                }

                try {
                    signalsSettings.getDynamicSettings().update(client, SignalsSettings.DynamicSettings.INTERNAL_AUTH_TOKEN_SIGNING_KEY.getKey(),
                            signingKey, SignalsSettings.DynamicSettings.INTERNAL_AUTH_TOKEN_ENCRYPTION_KEY.getKey(), encryptionKey);
                } catch (ConfigValidationException e) {
                    log.error("Could not init encryption keys. This should not happen", e);
                    throw new SignalsInitializationException("Could not init encryption keys. This should not happen", e);
                }
            }

            componentState.setState(State.INITIALIZING, "creating_tenants");

            if (configuredTenants != null) {
                log.debug("Initializing tenant schedulers");

                for (String tenant : configuredTenants) {
                    createTenant(tenant);
                }
            }

            failureListener.onSuccess();

            initState = InitializationState.INITIALIZED;
            componentState.setInitialized();
        } catch (SignalsInitializationException e) {
            failureListener.onFailure(e);
            initState = InitializationState.FAILED;
            initException = e;
            componentState.setFailed(e);
        }
    }

    private synchronized void updateTenants(Set<String> configuredTenants) {
        configuredTenants = new HashSet<>(configuredTenants);

        // ensure we always have a default tenant
        configuredTenants.add("_main");
        configuredTenants.remove("SGS_GLOBAL_TENANT");

        if (initState == InitializationState.INITIALIZED) {
            Set<String> currentTenants = this.tenants.keySet();

            for (String tenantToBeDeleted : Sets.difference(currentTenants, configuredTenants)) {
                try {
                    deleteTenant(tenantToBeDeleted);
                } catch (NoSuchTenantException e) {
                    log.debug("Tenant to be deleted does not exist", e);
                } catch (Exception e) {
                    log.error("Error while deleting tenant", e);
                }
            }

            for (String tenantToBeCreated : Sets.difference(configuredTenants, currentTenants)) {
                createTenant(tenantToBeCreated);
            }
        } else {
            this.configuredTenants = configuredTenants;
        }
    }

    private String generateKey(int bits) {
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[bits / 8];
        random.nextBytes(bytes);
        return BaseEncoding.base64().encode(bytes);
    }

    private void initEnterpriseModules() throws SignalsInitializationException {
        Class<?> signalsEnterpriseFeatures;

        try {

            signalsEnterpriseFeatures = Class.forName("org.opensearch.security.signals.enterprise.SignalsEnterpriseFeatures");

        } catch (ClassNotFoundException e) {
            throw new SignalsInitializationException("Signals enterprise features not found", e);
        }

        try {
            signalsEnterpriseFeatures.getDeclaredMethod("init").invoke(null);
        } catch (InvocationTargetException e) {
            throw new SignalsInitializationException("Error while initializing Signals enterprise features", e.getTargetException());
        } catch (IllegalAccessException | IllegalArgumentException | NoSuchMethodException | SecurityException e) {
            throw new SignalsInitializationException("Error while initializing Signals enterprise features", e);
        }
    }

    @Override
    protected void doStart() {
    }

    @Override
    protected void doStop() {

    }

    @Override
    protected void doClose() throws IOException {

    }

    public AccountRegistry getAccountRegistry() {
        return accountRegistry;
    }

    public SignalsSettings getSignalsSettings() {
        return signalsSettings;
    }

    synchronized void setInitException(Exception e) {
        if (initException != null) {
            return;
        }

        initException = e;
        initState = InitializationState.FAILED;
    }

    private final SignalsSettings.ChangeListener settingsChangeListener = new SignalsSettings.ChangeListener() {

        @Override
        public void onChange() {
            internalAuthTokenProvider.setSigningKey(signalsSettings.getDynamicSettings().getInternalAuthTokenSigningKey());
            internalAuthTokenProvider.setEncryptionKey(signalsSettings.getDynamicSettings().getInternalAuthTokenEncryptionKey());
        }
    };

    private final DCFListener dcfListener = new DCFListener() {
        @Override
        public void onChanged(ConfigModel cm, DynamicConfigModel dcm, InternalUsersModel ium) {
            log.debug("Tenant config model changed");
            updateTenants(cm.getAllConfiguredTenantNames());
        }
    };

    public enum InitializationState {
        INITIALIZING, INITIALIZED, FAILED, DISABLED
    }
}
