package org.opensearch.security.signals.watch.action.handlers;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.core.common.Strings;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.unit.TimeValue;

import org.opensearch.security.codova.validation.ConfigValidationException;
import org.opensearch.security.codova.validation.ValidationErrors;
import org.opensearch.security.searchsupport.config.elements.InlineMustacheTemplate;
import org.opensearch.security.searchsupport.config.validation.ValidatingJsonNode;
import org.opensearch.security.signals.execution.ActionExecutionException;
import org.opensearch.security.signals.execution.SimulationMode;
import org.opensearch.security.signals.execution.WatchExecutionContext;
import org.opensearch.security.signals.support.NestedValueMap;
import org.opensearch.security.signals.watch.init.WatchInitializationService;

public class IndexAction extends ActionHandler {
    private static final Logger log = LogManager.getLogger(IndexAction.class);

    public static final String TYPE = "index";

    private final String index;
    private InlineMustacheTemplate<String> docId;
    private Integer timeout;
    private RefreshPolicy refreshPolicy;

    public IndexAction(String index, RefreshPolicy refreshPolicy) {
        this.index = index;
        this.refreshPolicy = refreshPolicy;
    }

    @Override
    public ActionExecutionResult execute(WatchExecutionContext ctx) throws ActionExecutionException {

        NestedValueMap data = ctx.getContextData().getData();
        Object subDoc = data.get("_doc");

        if (subDoc instanceof Collection) {
            return indexMultiDoc(ctx, (Collection<?>) subDoc);
        } else if (subDoc instanceof Object[]) {
            return indexMultiDoc(ctx, Arrays.asList((Object[]) subDoc));
        } else {
            return indexSingleDoc(ctx, data);
        }
    }

    @Override
    public String getType() {
        return TYPE;
    }

    private ActionExecutionResult indexSingleDoc(WatchExecutionContext ctx, NestedValueMap data) throws ActionExecutionException {

        try {

            IndexRequest indexRequest = createIndexRequest(ctx, data, this.refreshPolicy);

            if (ctx.getSimulationMode() == SimulationMode.FOR_REAL) {
                IndexResponse indexResponse = ctx.getClient().index(indexRequest).get();
                
                if (log.isDebugEnabled()) {
                    log.debug("Result of " + this + ":\n" + Strings.toString(indexResponse));
                }
            }

            return new ActionExecutionResult(indexRequest);
        } catch (IOException | InterruptedException | ExecutionException e) {
            throw new ActionExecutionException(this, e);
        }
    }

    private ActionExecutionResult indexMultiDoc(WatchExecutionContext ctx, Collection<?> documents) throws ActionExecutionException {
        try {
            BulkRequest bulkRequest = new BulkRequest();

            for (Object data : documents) {
                if (data instanceof NestedValueMap) {
                    bulkRequest.add(createIndexRequest(ctx, (NestedValueMap) data, null));
                } else if (data instanceof Map) {
                    bulkRequest.add(createIndexRequest(ctx, NestedValueMap.copy((Map<?, ?>) data), null));

                }
            }

            if (refreshPolicy != null) {
                bulkRequest.setRefreshPolicy(refreshPolicy);
            }

            if (ctx.getSimulationMode() == SimulationMode.FOR_REAL) {
                BulkResponse response = ctx.getClient().bulk(bulkRequest).get();

                if (log.isDebugEnabled()) {
                    log.debug("Result of " + this + ":\n" + Strings.toString(response));
                }
                
                if (response.hasFailures()) {
                    throw new ActionExecutionException(this, "BulkRequest contains failures: " + response.buildFailureMessage());
                }
            }

            return new ActionExecutionResult(bulkRequest);

        } catch (IOException | InterruptedException | ExecutionException e) {
            throw new ActionExecutionException(this, e);
        }
    }

    private IndexRequest createIndexRequest(WatchExecutionContext ctx, NestedValueMap data, RefreshPolicy refreshPolicy) throws IOException {

        String index = this.index;

        if (data.get("_index") != null) {
            index = String.valueOf(data.get("_index"));
        }

        String docId = null;

        if (data.get("_id") != null) {
            docId = String.valueOf(data.get("_id"));
        }

        if (docId == null && this.docId != null) {
            docId = this.docId.render(ctx.getTemplateScriptParamsAsMap());
        }

        IndexRequest indexRequest = new IndexRequest(index);

        if (docId != null) {
            indexRequest.id(docId);
        }

        indexRequest.timeout(new TimeValue(timeout != null ? timeout : 60, TimeUnit.SECONDS));

        if (refreshPolicy != null) {
            indexRequest.setRefreshPolicy(refreshPolicy);
        }

        try (XContentBuilder jsonBuilder = XContentFactory.jsonBuilder()) {
            indexRequest.source(jsonBuilder.prettyPrint().map(data.without("_index", "_id")));
        }

        return indexRequest;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {

        if (timeout != null) {
            builder.field("timeout", timeout);
        }

        if (refreshPolicy != null) {
            builder.field("refresh", refreshPolicy.getValue());
        }

        if (index != null) {
            builder.field("index", index);
        }

        if (docId != null) {
            builder.field("doc_id", docId);
        }

        return builder;
    }

    public static class Factory extends ActionHandler.Factory<IndexAction> {
        public Factory() {
            super(IndexAction.TYPE);
        }

        @Override
        protected IndexAction create(WatchInitializationService watchInitService, ValidatingJsonNode vJsonNode, ValidationErrors validationErrors)
                throws ConfigValidationException {
            String index = vJsonNode.string("index");
            RefreshPolicy refreshPolicy = vJsonNode.value("refresh", (s) -> RefreshPolicy.parse(s), "true|false|wait_for", null);

            IndexAction result = new IndexAction(index, refreshPolicy);

            if (vJsonNode.hasNonNull("doc_id")) {
                result.docId = vJsonNode.template("doc_id");
            }

            if (vJsonNode.hasNonNull("timeout")) {
                result.timeout = vJsonNode.get("timeout").asInt();
            }

            return result;
        }
    }

    public InlineMustacheTemplate<String> getDocId() {
        return docId;
    }

    public void setDocId(InlineMustacheTemplate<String> docId) {
        this.docId = docId;
    }

    public void setDocId(String docId) {
        this.docId = InlineMustacheTemplate.constant(docId);
    }
}
