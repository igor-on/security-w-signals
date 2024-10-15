package org.opensearch.security.signals.watch.action.handlers;

import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Collections;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.xcontent.XContentBuilder;

import org.opensearch.security.codova.validation.ConfigValidationException;
import org.opensearch.security.codova.validation.ValidationErrors;
import org.opensearch.security.codova.validation.errors.MissingAttribute;
import org.opensearch.security.searchsupport.config.validation.ValidatingJsonNode;
import org.opensearch.security.signals.execution.ActionExecutionException;
import org.opensearch.security.signals.execution.SimulationMode;
import org.opensearch.security.signals.execution.WatchExecutionContext;
import org.opensearch.security.signals.execution.WatchExecutionException;
import org.opensearch.security.signals.watch.common.HttpClientConfig;
import org.opensearch.security.signals.watch.common.HttpRequestConfig;
import org.opensearch.security.signals.watch.common.HttpUtils;
import org.opensearch.security.signals.watch.common.WatchElement;
import org.opensearch.security.signals.watch.init.WatchInitializationService;
import com.google.common.collect.Iterables;

public class WebhookAction extends ActionHandler {
    private static final Logger log = LogManager.getLogger(WebhookAction.class);

    public static final String TYPE = "webhook";

    private final HttpRequestConfig requestConfig;
    private final HttpClientConfig httpClientConfig;

    public WebhookAction(HttpRequestConfig request, HttpClientConfig httpClientConfig) {
        this.requestConfig = request;
        this.httpClientConfig = httpClientConfig;
    }

    @Override
    public ActionExecutionResult execute(WatchExecutionContext ctx) throws ActionExecutionException {

        try (CloseableHttpClient httpClient = httpClientConfig.createHttpClient(ctx.getHttpProxyConfig())) {
            HttpUriRequest request = requestConfig.createHttpRequest(ctx);

            if (log.isDebugEnabled()) {
                log.debug("Going to execute: " + request);
            }

            if (ctx.getSimulationMode() == SimulationMode.FOR_REAL) {

                CloseableHttpResponse response = AccessController
                        .doPrivileged((PrivilegedExceptionAction<CloseableHttpResponse>) () -> httpClient.execute(request));

                if (response.getStatusLine().getStatusCode() >= 400) {
                    throw new WatchExecutionException(
                            "Web hook returned error: " + response.getStatusLine() + "\n\n" + HttpUtils.getEntityAsDebugString(response), null);
                }
            }

            return new ActionExecutionResult(HttpUtils.getRequestAsDebugString(request));
        } catch (PrivilegedActionException e) {
            throw new ActionExecutionException(this, e.getCause());
        } catch (Exception e) {
            throw new ActionExecutionException(this, e);
        }
    }

    @Override
    public String getType() {
        return TYPE;
    }

    @Override
    public Iterable<? extends WatchElement> getChildren() {
        return Iterables.concat(super.getChildren(), Collections.singletonList(this.requestConfig));
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {

        builder.field("request");
        requestConfig.toXContent(builder, params);

        httpClientConfig.toXContent(builder, params);

        return builder;
    }

    public static class Factory extends ActionHandler.Factory<WebhookAction> {
        public Factory() {
            super(WebhookAction.TYPE);
        }

        @Override
        protected WebhookAction create(WatchInitializationService watchInitService, ValidatingJsonNode vJsonNode, ValidationErrors validationErrors)
                throws ConfigValidationException {
            HttpClientConfig httpClientConfig = null;
            HttpRequestConfig request = null;

            if (vJsonNode.hasNonNull("request")) {
                try {
                    request = HttpRequestConfig.create(watchInitService, vJsonNode.get("request"));
                } catch (ConfigValidationException e) {
                    validationErrors.add("request", e);
                }
            } else {
                validationErrors.add(new MissingAttribute("request", vJsonNode));
            }

            try {
                httpClientConfig = HttpClientConfig.create(vJsonNode);
            } catch (ConfigValidationException e) {
                validationErrors.add(null, e);
            }
            //  vJsonNode.validateUnusedAttributes();

            validationErrors.throwExceptionForPresentErrors();

            return new WebhookAction(request, httpClientConfig);
        }
    }

}
