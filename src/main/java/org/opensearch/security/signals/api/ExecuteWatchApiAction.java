package org.opensearch.security.signals.api;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.action.ActionListener;
import org.opensearch.client.node.NodeClient;
import org.opensearch.common.settings.Settings;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.script.ScriptService;

import com.fasterxml.jackson.databind.JsonNode;
import org.opensearch.security.codova.validation.ConfigValidationException;
import org.opensearch.security.codova.validation.ValidationErrors;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.filter.TenantAwareRestHandler;
import org.opensearch.security.searchsupport.config.validation.ValidatingJsonParser;
import org.opensearch.security.searchsupport.json.JacksonTools;
import org.opensearch.security.signals.actions.watch.execute.ExecuteWatchAction;
import org.opensearch.security.signals.actions.watch.execute.ExecuteWatchRequest;
import org.opensearch.security.signals.actions.watch.execute.ExecuteWatchResponse;
import org.opensearch.security.signals.execution.SimulationMode;
import org.opensearch.security.signals.watch.Watch;
import org.opensearch.security.signals.watch.init.WatchInitializationService;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;

public class ExecuteWatchApiAction extends SignalsBaseRestHandler implements TenantAwareRestHandler {

    private final Logger log = LogManager.getLogger(this.getClass());
    private final ScriptService scriptService;

    public ExecuteWatchApiAction(Settings settings, ScriptService scriptService) {
        super(settings);
        this.scriptService = scriptService;
    }

    @Override
    public List<Route> routes() {
        return ImmutableList.of(new Route(Method.POST, "/_signals/watch/{tenant}/_execute"),
                new Route(Method.POST, "/_signals/watch/{tenant}/{id}/_execute"));
    }

    @Override
    protected final RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        try {

            final String id = request.param("id");
            request.param("tenant");

            final RequestBody requestBody = RequestBody.parse(new WatchInitializationService(null, scriptService), request.content().utf8ToString());

            if (log.isDebugEnabled()) {
                log.debug("Execute watch " + id + ":\n" + requestBody);
            }

            SimulationMode simulationMode = requestBody.isSkipActions() ? SimulationMode.SKIP_ACTIONS
                    : requestBody.isSimulate() ? SimulationMode.SIMULATE_ACTIONS : SimulationMode.FOR_REAL;

            ExecuteWatchRequest executeWatchRequest = new ExecuteWatchRequest(id,
                    requestBody.getWatch() != null ? requestBody.getWatch().toJson() : null, requestBody.isRecordExecution(), simulationMode,
                    requestBody.isShowAllRuntimeAttributes());

            if (requestBody.getInput() != null) {
                executeWatchRequest.setInputJson(DefaultObjectMapper.writeValueAsString(requestBody.getInput(), false));
            }

            executeWatchRequest.setGoTo(requestBody.getGoTo());

            return channel -> {
                client.execute(ExecuteWatchAction.INSTANCE, executeWatchRequest, new ActionListener<ExecuteWatchResponse>() {

                    @Override
                    public void onResponse(ExecuteWatchResponse response) {
                        if (response.getStatus() == ExecuteWatchResponse.Status.EXECUTED) {
                            channel.sendResponse(new BytesRestResponse(RestStatus.OK, "application/json", response.getResult()));
                        } else if (response.getStatus() == ExecuteWatchResponse.Status.NOT_FOUND) {
                            errorResponse(channel, RestStatus.NOT_FOUND, "No watch with id " + id);
                        } else if (response.getStatus() == ExecuteWatchResponse.Status.TENANT_NOT_FOUND) {
                            errorResponse(channel, RestStatus.NOT_FOUND, "Tenant does not exist");
                        } else if (response.getStatus() == ExecuteWatchResponse.Status.ERROR_WHILE_EXECUTING) {
                            channel.sendResponse(new BytesRestResponse(RestStatus.UNPROCESSABLE_ENTITY, "application/json", response.getResult()));
                        } else if (response.getStatus() == ExecuteWatchResponse.Status.INVALID_WATCH_DEFINITION) {
                            if (requestBody.getWatch() != null) {
                                channel.sendResponse(new BytesRestResponse(RestStatus.BAD_REQUEST, "application/json", response.getResult()));
                            } else {
                                errorResponse(channel, RestStatus.INTERNAL_SERVER_ERROR, "Internal Server Error: Stored watch cannot be parsed");
                            }
                        } else if (response.getStatus() == ExecuteWatchResponse.Status.INVALID_GOTO) {
                            errorResponse(channel, RestStatus.BAD_REQUEST, "Invalid goto value: " + requestBody.getGoTo());
                        } else {
                            errorResponse(channel, RestStatus.INTERNAL_SERVER_ERROR, "Internal Server Error");
                        }

                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error("Error while executing watch", e);
                        errorResponse(channel, e);
                    }
                });
            };

        } catch (ConfigValidationException e) {
            log.info("Error while parsing request body", e);

            return channel -> {
                errorResponse(channel, RestStatus.BAD_REQUEST, e.getMessage(), e.getValidationErrors().toJsonString());
            };
        }
    }

    @Override
    public String getName() {
        return "Execute Watch";
    }

    static class RequestBody {
        private Map<String, Object> input;
        private boolean recordExecution;
        private boolean simulate;
        private boolean skipActions;
        private boolean showAllRuntimeAttributes;
        private String goTo;
        private Watch watch;

        public Map<String, Object> getInput() {
            return input;
        }

        public void setInput(Map<String, Object> input) {
            this.input = input;
        }

        public boolean isRecordExecution() {
            return recordExecution;
        }

        public void setRecordExecution(boolean recordExecution) {
            this.recordExecution = recordExecution;
        }

        public Watch getWatch() {
            return watch;
        }

        public void setWatch(Watch watch) {
            this.watch = watch;
        }

        static RequestBody parse(WatchInitializationService initContext, String requestBody) throws ConfigValidationException {
            if (Strings.isNullOrEmpty(requestBody)) {
                return new RequestBody();
            }

            JsonNode rootNode = ValidatingJsonParser.readTree(requestBody);
            RequestBody result = new RequestBody();

            ValidationErrors validationErrors = new ValidationErrors();

            if (rootNode.hasNonNull("watch")) {
                try {
                    result.watch = Watch.parse(initContext, "anon", "anon_" + UUID.randomUUID(), rootNode.get("watch"));
                } catch (ConfigValidationException e) {
                    validationErrors.add("watch", e);
                }
            }

            if (rootNode.hasNonNull("input")) {
                result.input = JacksonTools.toMap(rootNode.get("input"));
            }

            if (rootNode.hasNonNull("record_execution")) {
                result.recordExecution = rootNode.get("record_execution").asBoolean();
            }

            if (rootNode.hasNonNull("simulate")) {
                result.simulate = rootNode.get("simulate").asBoolean();
            }

            if (rootNode.hasNonNull("skip_actions")) {
                result.skipActions = rootNode.get("skip_actions").asBoolean();
            }

            if (rootNode.hasNonNull("goto")) {
                result.goTo = rootNode.get("goto").asText();
            }

            if (rootNode.hasNonNull("show_all_runtime_attributes")) {
                result.showAllRuntimeAttributes = rootNode.get("show_all_runtime_attributes").asBoolean();
            }

            validationErrors.throwExceptionForPresentErrors();

            return result;

        }

        @Override
        public String toString() {
            return "RequestBody [alternativeInput=" + input + ", recordExecution=" + recordExecution + ", watch=" + watch + "]";
        }

        public boolean isSimulate() {
            return simulate;
        }

        public void setSimulate(boolean simulate) {
            this.simulate = simulate;
        }

        public boolean isSkipActions() {
            return skipActions;
        }

        public void setSkipActions(boolean skipActions) {
            this.skipActions = skipActions;
        }

        public String getGoTo() {
            return goTo;
        }

        public void setGoTo(String goTo) {
            this.goTo = goTo;
        }

        public boolean isShowAllRuntimeAttributes() {
            return showAllRuntimeAttributes;
        }

        public void setShowAllRuntimeAttributes(boolean showAllRuntimeAttributes) {
            this.showAllRuntimeAttributes = showAllRuntimeAttributes;
        }
    }
}
