package org.opensearch.security.signals.actions.watch.execute;

import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.action.ActionListener;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.util.concurrent.ThreadContext.StoredContext;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.script.ScriptService;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import org.opensearch.security.codova.validation.ConfigValidationException;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.security.searchsupport.diag.DiagnosticContext;
import org.opensearch.security.signals.NoSuchTenantException;
import org.opensearch.security.signals.Signals;
import org.opensearch.security.signals.SignalsTenant;
import org.opensearch.security.signals.SignalsUnavailableException;
import org.opensearch.security.signals.actions.watch.execute.ExecuteWatchResponse.Status;
import org.opensearch.security.signals.execution.ExecutionEnvironment;
import org.opensearch.security.signals.execution.GotoCheckSelector;
import org.opensearch.security.signals.execution.WatchExecutionException;
import org.opensearch.security.signals.execution.WatchRunner;
import org.opensearch.security.signals.settings.SignalsSettings;
import org.opensearch.security.signals.support.NestedValueMap;
import org.opensearch.security.signals.support.ToXParams;
import org.opensearch.security.signals.watch.Watch;
import org.opensearch.security.signals.watch.init.WatchInitializationService;
import org.opensearch.security.signals.watch.result.WatchLog;
import org.opensearch.security.signals.watch.result.WatchLogIndexWriter;
import org.opensearch.security.signals.watch.result.WatchLogWriter;
import com.google.common.base.Charsets;

public class TransportExecuteWatchAction extends HandledTransportAction<ExecuteWatchRequest, ExecuteWatchResponse> {

    private static final Logger log = LogManager.getLogger(TransportExecuteWatchAction.class);

    private final Signals signals;
    private final Client client;
    private final ThreadPool threadPool;
    private final ScriptService scriptService;
    private final NamedXContentRegistry xContentRegistry;
    private final Settings settings;
    private final ClusterService clusterService;
    private final DiagnosticContext diagnosticContext;

    @Inject
    public TransportExecuteWatchAction(Signals signals, TransportService transportService, ThreadPool threadPool, ActionFilters actionFilters,
            ScriptService scriptService, NamedXContentRegistry xContentRegistry, Client client, Settings settings, ClusterService clusterService,
            DiagnosticContext diagnosticContext) {
        super(ExecuteWatchAction.NAME, transportService, actionFilters, ExecuteWatchRequest::new);

        this.signals = signals;
        this.client = client;
        this.threadPool = threadPool;
        this.scriptService = scriptService;
        this.xContentRegistry = xContentRegistry;
        this.settings = settings;
        this.clusterService = clusterService;
        this.diagnosticContext = diagnosticContext;
    }

    @Override
    protected final void doExecute(Task task, ExecuteWatchRequest request, ActionListener<ExecuteWatchResponse> listener) {

        try {
            ThreadContext threadContext = threadPool.getThreadContext();

            User user = threadContext.getTransient(ConfigConstants.SG_USER);
            SignalsTenant signalsTenant = signals.getTenant(user);

            if (request.getWatchJson() != null) {
                executeAnonymousWatch(user, signalsTenant, task, request, listener);
            } else if (request.getWatchId() != null) {
                fetchAndExecuteWatch(user, signalsTenant, task, request, listener);
            }
        } catch (NoSuchTenantException e) {
            listener.onResponse(new ExecuteWatchResponse(e.getTenant(), request.getWatchId(), ExecuteWatchResponse.Status.TENANT_NOT_FOUND, null));
        } catch (SignalsUnavailableException e) {
            listener.onFailure(e.toElasticsearchException());
        } catch (Exception e) {
            listener.onFailure(e);
        } catch (Throwable t) {
            log.error(t);
        }
    }

    private void fetchAndExecuteWatch(User user, SignalsTenant signalsTenant, Task task, ExecuteWatchRequest request,
            ActionListener<ExecuteWatchResponse> listener) {
        ThreadContext threadContext = threadPool.getThreadContext();

        Object remoteAddress = threadContext.getTransient(ConfigConstants.SG_REMOTE_ADDRESS);
        Object origin = threadContext.getTransient(ConfigConstants.SG_ORIGIN);

        try (StoredContext ctx = threadPool.getThreadContext().stashContext()) {
            threadContext.putHeader(ConfigConstants.SG_CONF_REQUEST_HEADER, "true");
            threadContext.putTransient(ConfigConstants.SG_USER, user);
            threadContext.putTransient(ConfigConstants.SG_REMOTE_ADDRESS, remoteAddress);
            threadContext.putTransient(ConfigConstants.SG_ORIGIN, origin);

            client.prepareGet(signalsTenant.getConfigIndexName(), null, signalsTenant.getWatchIdForConfigIndex(request.getWatchId()))
                    .execute(new ActionListener<GetResponse>() {

                        @Override
                        public void onResponse(GetResponse response) {

                            try {
                                if (!response.isExists()) {
                                    listener.onResponse(new ExecuteWatchResponse(user != null ? user.getRequestedTenant() : null,
                                            request.getWatchId(), ExecuteWatchResponse.Status.NOT_FOUND, null));
                                    return;
                                }

                                Watch watch = Watch.parse(new WatchInitializationService(signals.getAccountRegistry(), scriptService),
                                        signalsTenant.getName(), request.getWatchId(), response.getSourceAsString(), response.getVersion());

                                try (StoredContext ctx = threadPool.getThreadContext().stashContext()) {
                                    threadContext.putTransient(ConfigConstants.SG_USER, user);
                                    threadContext.putTransient(ConfigConstants.SG_REMOTE_ADDRESS, remoteAddress);
                                    threadContext.putTransient(ConfigConstants.SG_ORIGIN, origin);

                                    listener.onResponse(executeWatch(watch, request, signalsTenant));

                                }

                            } catch (ConfigValidationException e) {
                                log.error("Invalid watch definition in fetchAndExecuteWatch(). This should not happen\n"
                                        + response.getSourceAsString() + "\n" + e.getValidationErrors(), e);
                                listener.onResponse(new ExecuteWatchResponse(signalsTenant.getName(), request.getWatchId(),
                                        ExecuteWatchResponse.Status.INVALID_WATCH_DEFINITION,
                                        new BytesArray(e.toJsonString().getBytes(Charsets.UTF_8))));
                            } catch (Exception e) {
                                listener.onFailure(e);
                            }
                        }

                        @Override
                        public void onFailure(Exception e) {
                            listener.onFailure(e);
                        }

                    });

        } catch (Exception e) {
            listener.onFailure(e);
        }
    }

    private void executeAnonymousWatch(User user, SignalsTenant signalsTenant, Task task, ExecuteWatchRequest request,
            ActionListener<ExecuteWatchResponse> listener) {

        try {
            Watch watch = Watch.parse(new WatchInitializationService(signals.getAccountRegistry(), scriptService), signalsTenant.getName(),
                    "__inline_watch", request.getWatchJson(), -1);

            threadPool.generic().submit(threadPool.getThreadContext().preserveContext(() -> {
                try {
                    listener.onResponse(executeWatch(watch, request, signalsTenant));
                } catch (Exception e) {
                    listener.onFailure(e);
                }
            }));

        } catch (ConfigValidationException e) {
            listener.onResponse(new ExecuteWatchResponse(signalsTenant.getName(), request.getWatchId(),
                    ExecuteWatchResponse.Status.INVALID_WATCH_DEFINITION, new BytesArray(e.toJsonString().getBytes(Charsets.UTF_8))));
        } catch (Exception e) {
            log.error("Error while executing anonymous watch " + request, e);
            listener.onFailure(e);
        }
    }

    private ExecuteWatchResponse executeWatch(Watch watch, ExecuteWatchRequest request, SignalsTenant signalsTenant) {

        WatchLogWriter watchLogWriter = null;
        NestedValueMap input = null;
        GotoCheckSelector checkSelector = null;

        ToXContent.Params watchLogToXparams = ToXParams.of(WatchLog.ToXContentParams.INCLUDE_DATA, !request.isIncludeAllRuntimeAttributesInResponse(),
                WatchLog.ToXContentParams.INCLUDE_RUNTIME_ATTRIBUTES, request.isIncludeAllRuntimeAttributesInResponse());

        if (request.isRecordExecution()) {
            watchLogWriter = WatchLogIndexWriter.forTenant(client, signalsTenant.getName(), new SignalsSettings(settings), watchLogToXparams);
        }

        if (request.getInputJson() != null) {
            try {
                input = NestedValueMap.fromJsonString(request.getInputJson());
            } catch (IOException e) {
                log.info("Error while parsing json: " + request.getInputJson(), e);
                return new ExecuteWatchResponse(null, request.getWatchId(), Status.INVALID_INPUT, null);
            }
        }

        if (request.getGoTo() != null) {
            try {
                checkSelector = new GotoCheckSelector(watch, request.getGoTo());
            } catch (IllegalArgumentException e) {
                log.info("Error while parsing goTo: " + e);
                return new ExecuteWatchResponse(null, request.getWatchId(), Status.INVALID_GOTO, null);
            }
        }

        WatchRunner watchRunner = new WatchRunner(watch, client, signals.getAccountRegistry(), scriptService, watchLogWriter, null, diagnosticContext,
                null, ExecutionEnvironment.TEST, request.getSimulationMode(), xContentRegistry, signals.getSignalsSettings(),
                clusterService.getNodeName(), checkSelector, input);

        try {
            WatchLog watchLog = watchRunner.execute();

            return new ExecuteWatchResponse(null, request.getWatchId(), Status.EXECUTED, toBytesReference(watchLog, watchLogToXparams));

        } catch (WatchExecutionException e) {
            log.info("Error while manually executing watch", e);
            return new ExecuteWatchResponse(null, request.getWatchId(), Status.ERROR_WHILE_EXECUTING,
                    toBytesReference(e.getWatchLog(), watchLogToXparams));
        }
    }

    private BytesReference toBytesReference(ToXContent toXContent, ToXContent.Params toXparams) {
        try {
            XContentBuilder builder = JsonXContent.contentBuilder();
            toXContent.toXContent(builder, toXparams);
            return BytesReference.bytes(builder);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}