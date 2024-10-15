package org.opensearch.security.signals;

import java.io.Closeable;
import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.action.ActionListener;
import org.opensearch.action.DocWriteResponse.Result;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.common.Strings;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.script.ScriptService;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.quartz.Job;
import org.quartz.Scheduler;
import org.quartz.SchedulerException;
import org.quartz.impl.matchers.GroupMatcher;
import org.quartz.spi.JobFactory;
import org.quartz.spi.TriggerFiredBundle;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.opensearch.security.codova.validation.ConfigValidationException;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.internalauthtoken.InternalAuthTokenProvider;
import org.opensearch.security.modules.state.ComponentState;
import org.opensearch.security.modules.state.ComponentState.State;
import org.opensearch.security.support.PrivilegedConfigClient;
import org.opensearch.security.user.User;
import org.opensearch.security.searchsupport.config.validation.ValidatingJsonParser;
import org.opensearch.security.searchsupport.diag.DiagnosticContext;
import org.opensearch.security.searchsupport.jobs.JobConfigListener;
import org.opensearch.security.searchsupport.jobs.SchedulerBuilder;
import org.opensearch.security.searchsupport.jobs.actions.SchedulerConfigUpdateAction;
import org.opensearch.security.searchsupport.jobs.config.JobDetailWithBaseConfig;
import org.opensearch.security.signals.accounts.AccountRegistry;
import org.opensearch.security.signals.execution.ExecutionEnvironment;
import org.opensearch.security.signals.execution.SimulationMode;
import org.opensearch.security.signals.execution.WatchRunner;
import org.opensearch.security.signals.settings.SignalsSettings;
import org.opensearch.security.signals.support.ToXParams;
import org.opensearch.security.signals.watch.Watch;
import org.opensearch.security.signals.watch.init.WatchInitializationService;
import org.opensearch.security.signals.watch.result.WatchLog;
import org.opensearch.security.signals.watch.result.WatchLogIndexWriter;
import org.opensearch.security.signals.watch.result.WatchLogWriter;
import org.opensearch.security.signals.watch.state.WatchState;
import org.opensearch.security.signals.watch.state.WatchStateIndexReader;
import org.opensearch.security.signals.watch.state.WatchStateIndexWriter;
import org.opensearch.security.signals.watch.state.WatchStateManager;

public class SignalsTenant implements Closeable {
    private static final Logger log = LogManager.getLogger(SignalsTenant.class);

    public static SignalsTenant create(String name, Client client, ClusterService clusterService, NodeEnvironment nodeEnvironment,
            ScriptService scriptService, NamedXContentRegistry xContentRegistry, InternalAuthTokenProvider internalAuthTokenProvider,
            SignalsSettings settings, AccountRegistry accountRegistry, ComponentState tenantState, DiagnosticContext diagnosticContext)
            throws SchedulerException {
        SignalsTenant instance = new SignalsTenant(name, client, clusterService, nodeEnvironment, scriptService, xContentRegistry,
                internalAuthTokenProvider, settings, accountRegistry, tenantState, diagnosticContext);

        instance.init();

        return instance;
    }

    private final SignalsSettings settings;
    private final String name;
    private final String scopedName;
    private final String configIndexName;
    private final String watchIdPrefix;
    private final Client privilegedConfigClient;
    private final Client client;
    private final ClusterService clusterService;
    private final NodeEnvironment nodeEnvironment;
    private String nodeFilter;
    private final NamedXContentRegistry xContentRegistry;
    private final ScriptService scriptService;
    private final WatchStateManager watchStateManager;
    private final WatchStateIndexWriter watchStateWriter;
    private final WatchStateIndexReader watchStateReader;
    private final InternalAuthTokenProvider internalAuthTokenProvider;
    private final AccountRegistry accountRegistry;
    private final String nodeName;
    private final ComponentState tenantState;
    private SignalsSettings.Tenant tenantSettings;
    private final DiagnosticContext diagnosticContext;

    private Scheduler scheduler;

    public SignalsTenant(String name, Client client, ClusterService clusterService, NodeEnvironment nodeEnvironment, ScriptService scriptService,
            NamedXContentRegistry xContentRegistry, InternalAuthTokenProvider internalAuthTokenProvider, SignalsSettings settings,
            AccountRegistry accountRegistry, ComponentState tenantState, DiagnosticContext diagnosticContext) {
        this.name = name;
        this.settings = settings;
        this.scopedName = "signals/" + name;
        this.configIndexName = settings.getStaticSettings().getIndexNames().getWatches();
        this.watchIdPrefix = name.replace("/", "\\/") + "/";
        this.client = client;
        this.privilegedConfigClient = new PrivilegedConfigClient(client);
        this.clusterService = clusterService;
        this.nodeEnvironment = nodeEnvironment;
        this.scriptService = scriptService;
        this.xContentRegistry = xContentRegistry;
        this.tenantSettings = settings.getTenant(name);
        this.nodeFilter = tenantSettings.getNodeFilter();
        this.watchStateManager = new WatchStateManager(name, clusterService.getNodeName());
        this.watchStateWriter = new WatchStateIndexWriter(watchIdPrefix, settings.getStaticSettings().getIndexNames().getWatchesState(),
                privilegedConfigClient);
        this.watchStateReader = new WatchStateIndexReader(name, watchIdPrefix, settings.getStaticSettings().getIndexNames().getWatchesState(),
                privilegedConfigClient);
        this.internalAuthTokenProvider = internalAuthTokenProvider;
        this.accountRegistry = accountRegistry;
        this.nodeName = clusterService.getNodeName();
        this.tenantState = tenantState;
        this.diagnosticContext = diagnosticContext;

        settings.addChangeListener(this.settingsChangeListener);
    }

    public SignalsTenant(String name, Client client, ClusterService clusterService, NodeEnvironment nodeEnvironment, ScriptService scriptService,
            NamedXContentRegistry xContentRegistry, InternalAuthTokenProvider internalAuthTokenProvider, SignalsSettings settings,
            AccountRegistry accountRegistry, DiagnosticContext diagnosticContext) {
        this(name, client, clusterService, nodeEnvironment, scriptService, xContentRegistry, internalAuthTokenProvider, settings, accountRegistry,
                new ComponentState(0, null, "tenant"), diagnosticContext);
    }

    public void init() throws SchedulerException {
        if (this.tenantSettings.isActive()) {
            doInit();
        } else {
            this.tenantState.setState(State.SUSPENDED);
        }
    }

    private void doInit() throws SchedulerException {
        log.info("Initializing alerting tenant " + name + "\nnodeFilter: " + nodeFilter);
        tenantState.setState(ComponentState.State.INITIALIZING);

        this.scheduler = new SchedulerBuilder<Watch>()//
                .client(privilegedConfigClient)//
                .name(scopedName)//
                .configIndex(configIndexName, getActiveConfigQuery(name))//
                .stateIndex(settings.getStaticSettings().getIndexNames().getWatchesTriggerState())//
                .stateIndexIdPrefix(watchIdPrefix)//
                .jobConfigFactory(new Watch.JobConfigFactory(name, watchIdPrefix, new WatchInitializationService(accountRegistry, scriptService)))//
                .distributed(clusterService, nodeEnvironment)//
                .jobFactory(jobFactory)//
                .nodeFilter(nodeFilter)//
                .jobConfigListener(jobConfigListener)//
                .maxThreads(settings.getStaticSettings().getMaxThreads())//
                .threadKeepAlive(settings.getStaticSettings().getThreadKeepAlive())//
                .threadPriority(settings.getStaticSettings().getThreadPrio())//
                .build();
        this.scheduler.start();
    }

    public void pause() throws SchedulerException {
        log.info("Suspending scheduler of " + this);

        if (this.scheduler != null) {
            this.tenantState.setState(State.SUSPENDED);
            this.scheduler.standby();
        }
    }

    public void resume() throws SchedulerException {
        if (this.scheduler == null || this.scheduler.isShutdown()) {
            doInit();
        } else if (!this.scheduler.isStarted() || this.scheduler.isInStandbyMode()) {
            log.info("Resuming scheduler of " + this);
            this.tenantState.setState(State.INITIALIZED);
            this.scheduler.start();
        } else {
            log.info("Scheduler is already active " + this);
        }
    }

    public boolean isActive() throws SchedulerException {
        return this.scheduler != null && this.scheduler.isStarted() && !this.scheduler.isInStandbyMode();
    }

    public void shutdown() {
        try {
            if (this.scheduler != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Going to shutdown " + this.scheduler);
                }

                this.scheduler.shutdown(true);
                tenantState.setState(ComponentState.State.DISABLED);
            }
        } catch (SchedulerException e) {
            log.error("Error wile shutting down " + this, e);
        }
    }

    public void shutdownHard() {
        try {
            if (this.scheduler != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Going to shutdown " + this.scheduler);
                }

                this.scheduler.shutdown(false);
                tenantState.setState(ComponentState.State.DISABLED);
                this.scheduler = null;
            }
        } catch (SchedulerException e) {
            log.error("Error wile shutting down " + this, e);
        }
    }

    public synchronized void restart() throws SchedulerException {
        shutdown();
        init();
    }

    public void restartAsync() {
        new Thread() {
            public void run() {
                try {
                    restart();
                } catch (SchedulerException e) {
                    log.error("Error while restarting: " + SignalsTenant.this, e);
                }
            }
        }.start();
    }

    public boolean runsWatchLocally(String watchId) {
        try {
            return this.scheduler != null && this.scheduler.getJobDetail(Watch.createJobKey(watchId)) != null;
        } catch (SchedulerException e) {
            throw new RuntimeException(e);
        }
    }

    public int getLocalWatchCount() {
        try {
            if (this.scheduler == null) {
                return 0;
            }

            // Note: The following call is synchronized on the job store, so use this call with care
            return this.scheduler.getJobKeys(GroupMatcher.anyJobGroup()).size();
        } catch (SchedulerException e) {
            throw new RuntimeException(e);
        }
    }

    public String getWatchIdForConfigIndex(String watchId) {
        return watchIdPrefix + watchId;
    }

    public String getWatchIdForConfigIndex(Watch watch) {
        return getWatchIdForConfigIndex(watch.getId());
    }

    public IndexResponse addWatch(Watch watch, User user) throws IOException {

        try {
            return addWatch(watch.getId(), Strings.toString(MediaTypeRegistry.JSON ,watch), user);
        } catch (ConfigValidationException e) {
            // This should not happen
            throw new RuntimeException(e);
        }
    }

    public IndexResponse addWatch(String watchId, String watchJsonString, User user) throws ConfigValidationException, IOException {

        if (log.isInfoEnabled()) {
            log.info("addWatch(" + watchId + ") on " + this);
        }

        ObjectNode watchJson = ValidatingJsonParser.readObject(watchJsonString);

        Watch watch = Watch.parse(new WatchInitializationService(accountRegistry, scriptService), getName(), watchId, watchJson, -1);

        watch.setTenant(name);
        watch.getMeta().setLastEditByUser(user.getName());
        watch.getMeta().setLastEditByDate(new Date());
        watch.getMeta().setAuthToken(internalAuthTokenProvider.getJwt(user, watch.getIdAndHash()));

        watchJson.put("_tenant", watch.getTenant());
        watchJson.set("_meta", watch.getMeta().toJsonNode());
        watchJson.put("_name", watchId);


        String newWatchJsonString = DefaultObjectMapper.writeJsonTree(watchJson);

//        IndexResponse indexResponse = privilegedConfigClient.prepareIndex(getConfigIndexName(), null, getWatchIdForConfigIndex(watch.getId()))
        // TODO: IGOR_ON CHANGE
        IndexResponse indexResponse = privilegedConfigClient.prepareIndex(getConfigIndexName())
                .setSource(newWatchJsonString, XContentType.JSON).setRefreshPolicy(RefreshPolicy.IMMEDIATE).execute().actionGet();

        if (log.isDebugEnabled()) {
            log.debug("IndexResponse from addWatch()\n" + Strings.toString(MediaTypeRegistry.JSON ,indexResponse));
        }

        if (indexResponse.getResult() == Result.CREATED) {
            watchStateWriter.put(watch.getId(), new WatchState(name), new ActionListener<IndexResponse>() {

                @Override
                public void onResponse(IndexResponse response) {
                    SchedulerConfigUpdateAction.send(privilegedConfigClient, getScopedName());
                }

                @Override
                public void onFailure(Exception e) {
                    log.warn("Error while writing initial state for " + watch + ". Ignoring", e);
                    SchedulerConfigUpdateAction.send(privilegedConfigClient, getScopedName());
                }

            });
        } else if (indexResponse.getResult() == Result.UPDATED) {
            SchedulerConfigUpdateAction.send(privilegedConfigClient, getScopedName());
        }

        return indexResponse;
    }

    public List<String> ack(String watchId, User user) {
        if (log.isInfoEnabled()) {
            log.info("ack(" + watchId + ", " + user + ")");
        }

        WatchState watchState = watchStateManager.getWatchState(watchId);

        List<String> result = watchState.ack(user != null ? user.getName() : null);

        watchStateWriter.put(watchId, watchState);

        return result;
    }

    public void ack(String watchId, String actionId, User user) {
        if (log.isInfoEnabled()) {
            log.info("ack(" + watchId + ", " + actionId + ", " + user + ")");
        }

        WatchState watchState = watchStateManager.getWatchState(watchId);

        watchState.getActionState(actionId).ack(user != null ? user.getName() : null);

        watchStateWriter.put(watchId, watchState);
    }

    public List<String> unack(String watchId, User user) throws NoSuchWatchOnThisNodeException {
        if (log.isInfoEnabled()) {
            log.info("unack(" + watchId + ", " + user + ")");
        }

        WatchState watchState = watchStateManager.peekWatchState(watchId);

        if (watchState == null) {
            throw new NoSuchWatchOnThisNodeException(watchId, nodeName);
        }

        List<String> result = watchState.unack(user != null ? user.getName() : null);

        if (log.isDebugEnabled()) {
            log.debug("Unacked actions: " + result);
        }

        watchStateWriter.put(watchId, watchState);

        return result;
    }

    public boolean unack(String watchId, String actionId, User user) throws NoSuchWatchOnThisNodeException {
        if (log.isInfoEnabled()) {
            log.info("unack(" + watchId + ", " + actionId + ", " + user + ")");
        }

        WatchState watchState = watchStateManager.peekWatchState(watchId);

        if (watchState == null) {
            throw new NoSuchWatchOnThisNodeException(watchId, nodeName);
        }

        boolean result = watchState.getActionState(actionId).unackIfPossible(user != null ? user.getName() : null);

        watchStateWriter.put(watchId, watchState);

        return result;
    }

    public WatchState getWatchState(String watchId) {
        return watchStateManager.getWatchState(watchId);
    }

    public void deleteTenantFromIndexes() {
        log.info("Deleting watches of " + this);

        SearchRequest searchRequest = new SearchRequest(this.configIndexName);
        searchRequest.source(new SearchSourceBuilder().query(getConfigQuery(this.name)).size(10000));
        // TODO scrolling

        SearchResponse searchResponse = this.privilegedConfigClient.search(searchRequest).actionGet();

        int seen = 0;
        int deletedWatches = 0;
        int deletedWatchStates = 0;

        for (SearchHit hit : searchResponse.getHits()) {
            seen++;

            DeleteResponse watchDeleteResponse = this.privilegedConfigClient.delete(new DeleteRequest(this.configIndexName, hit.getId())).actionGet();
            deletedWatches += watchDeleteResponse.getResult() == Result.DELETED ? 1 : 0;

            DeleteResponse watchStateDeleteResponse = this.privilegedConfigClient
                    .delete(new DeleteRequest(this.settings.getStaticSettings().getIndexNames().getWatchesState(), hit.getId())).actionGet();
            deletedWatchStates += watchStateDeleteResponse.getResult() == Result.DELETED ? 1 : 0;

            // TODO triggers
        }

        log.info("Deleted of  " + seen + ":\n" + deletedWatches + " watches\n" + deletedWatchStates + " watch states");
    }

    public void delete() {
        this.settings.removeChangeListener(this.settingsChangeListener);
        this.shutdown();
    }

    private final JobFactory jobFactory = new JobFactory() {

        @Override
        public Job newJob(TriggerFiredBundle bundle, Scheduler scheduler) throws SchedulerException {
            Watch watch = getConfig(bundle);

            if (log.isDebugEnabled()) {
                log.debug("newJob() on " + SignalsTenant.this + "@" + SignalsTenant.this.hashCode() + ": " + watch);
            }

            WatchState watchState = watchStateManager.getWatchState(watch.getId());

            if (watchState.isRefreshBeforeExecuting()) {
                watchState = refreshState(watch, watchState);
            }

            WatchLogWriter watchLogWriter = WatchLogIndexWriter.forTenant(client, name, settings,
                    ToXParams.of(WatchLog.ToXContentParams.INCLUDE_DATA, watch.isLogRuntimeData()));

            return new WatchRunner(watch, client, accountRegistry, scriptService, watchLogWriter, watchStateWriter, diagnosticContext, watchState,
                    ExecutionEnvironment.SCHEDULED, SimulationMode.FOR_REAL, xContentRegistry, settings, nodeName, null, null);
        }

        private Watch getConfig(TriggerFiredBundle bundle) {
            return ((JobDetailWithBaseConfig) bundle.getJobDetail()).getBaseConfig(Watch.class);
        }

        private WatchState refreshState(Watch watch, WatchState oldState) {
            try {
                if (log.isDebugEnabled()) {
                    log.debug("Refreshing state for " + watch.getId() + "\nOld state: " + (oldState != null ? Strings.toString(MediaTypeRegistry.JSON ,oldState) : null));
                }
                WatchState newState = watchStateReader.get(watch.getId());

                if (newState.getNode() == null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Got refreshed state for " + watch.getId()
                                + "\nThis however has a null node. Thus, it is probably the initial default state. Discarding: "
                                + (oldState != null ? Strings.toString(MediaTypeRegistry.JSON ,oldState) : null));
                    }

                    return oldState;
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Refreshed state for " + watch.getId() + "\nNew state: " + (oldState != null ? Strings.toString(MediaTypeRegistry.JSON ,oldState) : null));
                    }

                    newState.setNode(nodeName);
                    return newState;
                }

            } catch (Exception e) {
                log.error("Error while refreshing WatchState of " + watch.getId() + ";\nUsing original state", e);
                return oldState;
            }
        }

    };

    private final JobConfigListener<Watch> jobConfigListener = new JobConfigListener<Watch>() {

        @Override
        public void onInit(Set<Watch> watches) {
            Set<String> watchIds = watches.stream().map((watch) -> watch.getId()).collect(Collectors.toSet());

            tenantState.setState(State.INITIALIZING, "reading_states");

            Map<String, WatchState> dirtyStates = watchStateManager.reset(watchStateReader.get(watchIds), watchIds);

            if (!dirtyStates.isEmpty()) {
                tenantState.setState(State.INITIALIZING, "writing_states");

                watchStateWriter.putAll(dirtyStates);
            }

            tenantState.setState(State.INITIALIZED);
        }

        @Override
        public void beforeChange(Set<Watch> newJobs) {
            if (newJobs != null && newJobs.size() > 0) {
                Set<String> watchIds = newJobs.stream().map((watch) -> watch.getId()).collect(Collectors.toSet());

                tenantState.setState(State.INITIALIZING, "reading_states");

                if (log.isDebugEnabled()) {
                    log.debug("Reading states of newly arrived watches from index: " + watchIds);
                }

                Map<String, WatchState> statesFromIndex = watchStateReader.get(watchIds);

                Map<String, WatchState> dirtyStates = watchStateManager.add(statesFromIndex, watchIds);

                if (!dirtyStates.isEmpty()) {
                    tenantState.setState(State.INITIALIZING, "writing_states");

                    if (log.isDebugEnabled()) {
                        log.debug("Updating dirty states: " + dirtyStates);
                    }

                    watchStateWriter.putAll(dirtyStates);
                }

                tenantState.setState(State.INITIALIZED);
            }
        }

        @Override
        public void afterChange(Set<Watch> newJobs, Map<Watch, Watch> updatedJobs, Set<Watch> deletedJobs) {
            for (Watch deletedWatch : deletedJobs) {
                watchStateManager.delete(deletedWatch.getId());
            }
        }

    };

    public WatchStateManager getWatchStateManager() {
        return watchStateManager;
    }

    private QueryBuilder getActiveConfigQuery(String tenant) {
        return QueryBuilders.boolQuery().must(getConfigQuery(tenant)).mustNot(QueryBuilders.termQuery("active", false));
    }

    private QueryBuilder getConfigQuery(String tenant) {
        return QueryBuilders.boolQuery().must(QueryBuilders.termQuery("_tenant", tenant));
    }

    public String getName() {
        return name;
    }

    public String getConfigIndexName() {
        return configIndexName;
    }

    public String getScopedName() {
        return scopedName;
    }

    @Override
    public void close() throws IOException {
        this.shutdown();
    }

    private final SignalsSettings.ChangeListener settingsChangeListener = new SignalsSettings.ChangeListener() {

        @Override
        public void onChange() {

            try {
                tenantSettings = settings.getTenant(name);

                if (!Objects.equals(nodeFilter, tenantSettings.getNodeFilter())) {
                    log.info("Restarting tenant " + name + " because node filter has changed: " + nodeFilter + " <> "
                            + tenantSettings.getNodeFilter());
                    nodeFilter = tenantSettings.getNodeFilter();
                    restartAsync();
                }

                boolean active = tenantSettings.isActive() && settings.getDynamicSettings().isActive();

                if (active != isActive()) {
                    if (active) {
                        resume();
                    } else {
                        pause();
                    }
                }
            } catch (SchedulerException e) {
                log.error("Error in " + this, e);
            }

        }
    };

    @Override
    public String toString() {
        return "SignalsTenant " + name;
    }

    public WatchStateIndexReader getWatchStateReader() {
        return watchStateReader;
    }

    public SignalsSettings getSettings() {
        return settings;
    }
}
