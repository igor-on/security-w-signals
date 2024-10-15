package org.opensearch.security.signals.execution;

import java.io.IOException;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.script.JodaCompatibleZonedDateTime;

import com.fasterxml.jackson.databind.JsonNode;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.searchsupport.xcontent.ObjectTreeXContent;
import org.opensearch.security.signals.support.NestedValueMap;
import org.opensearch.security.signals.watch.severity.SeverityMapping;

public class WatchExecutionContextData implements ToXContentObject {
    private static final Logger log = LogManager.getLogger(WatchExecutionContextData.class);

    private NestedValueMap data;
    private NestedValueMap item;
    private SeverityMapping.EvaluationResult severity;
    private TriggerInfo triggerInfo;
    private JodaCompatibleZonedDateTime executionTime;
    private WatchInfo watch;

    public WatchExecutionContextData() {
        this.data = new NestedValueMap();
        this.triggerInfo = new TriggerInfo();
    }
    
    public WatchExecutionContextData(WatchInfo watch) {
        this.data = new NestedValueMap();
        this.triggerInfo = new TriggerInfo();
        this.watch = watch;
    }

    public WatchExecutionContextData(NestedValueMap data) {
        this.data = data;
        this.triggerInfo = new TriggerInfo();
        this.watch = new WatchInfo(null, null);
    }
    
    public WatchExecutionContextData(NestedValueMap data, WatchInfo watch) {
        this.data = data;
        this.triggerInfo = new TriggerInfo();
        this.watch = watch;
    }

    public WatchExecutionContextData(NestedValueMap data, WatchInfo watch, TriggerInfo triggerInfo, JodaCompatibleZonedDateTime executionTime) {
        this.data = data;
        this.triggerInfo = triggerInfo;
        this.executionTime = executionTime;
        this.watch = watch;
    }

    public WatchExecutionContextData(NestedValueMap data, WatchInfo watch, TriggerInfo triggerInfo, JodaCompatibleZonedDateTime executionTime,
            SeverityMapping.EvaluationResult severity) {
        this.data = data;
        this.triggerInfo = triggerInfo;
        this.executionTime = executionTime;
        this.severity = severity;
        this.watch = watch;
    }

    public WatchExecutionContextData(NestedValueMap data, WatchInfo watch, TriggerInfo triggerInfo, JodaCompatibleZonedDateTime executionTime,
            SeverityMapping.EvaluationResult severity, NestedValueMap item) {
        this.data = data;
        this.triggerInfo = triggerInfo;
        this.executionTime = executionTime;
        this.severity = severity;
        this.item = item;
        this.watch = watch;
    }

    public Map<String, Object> getTemplateScriptParamsAsMap() {
        Map<String, Object> result = new HashMap<>();
        result.put("data", getData());
        result.put("item", getItem());
        result.put("severity", severity != null ? severity.toMap() : null);
        result.put("trigger", triggerInfo != null ? triggerInfo.toMap() : null);
        result.put("execution_time", executionTime);
        result.put("watch", watch != null ? watch.toMap() : null);

        return result;
    }

    public NestedValueMap getData() {
        return data;
    }

    public void setData(NestedValueMap data) {
        this.data = data;
    }

    public SeverityMapping.EvaluationResult getSeverity() {
        return severity;
    }

    public void setSeverity(SeverityMapping.EvaluationResult severity) {
        this.severity = severity;
    }

    public TriggerInfo getTriggerInfo() {
        return triggerInfo;
    }

    public void setTriggerInfo(TriggerInfo triggerInfo) {
        this.triggerInfo = triggerInfo;
    }

    public JodaCompatibleZonedDateTime getExecutionTime() {
        return executionTime;
    }

    public void setExecutionTime(JodaCompatibleZonedDateTime executionTime) {
        this.executionTime = executionTime;
    }

    public WatchExecutionContextData clone() {
        return new WatchExecutionContextData(data.clone(), watch, triggerInfo, executionTime, severity, item);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("watch", watch);
        builder.field("data", data);
        builder.field("severity", severity);
        builder.field("trigger", triggerInfo);
        builder.field("execution_time", executionTime);
        builder.endObject();
        return builder;
    }

    public static WatchExecutionContextData create(JsonNode jsonNode) {
        WatchExecutionContextData result = new WatchExecutionContextData();

        if (jsonNode.hasNonNull("data")) {
            try {
                result.data = NestedValueMap.createUnmodifieableMap(DefaultObjectMapper.readTree(jsonNode.get("data"), Map.class));
            } catch (Exception e) {
                log.error("Error while parsing " + jsonNode.get("data"), e);
            }
        }

        if (jsonNode.hasNonNull("severity")) {
            try {
                result.severity = SeverityMapping.EvaluationResult.create(jsonNode.get("severity"));
            } catch (Exception e) {
                log.error("Error while parsing " + jsonNode.get("severity"), e);
            }
        }

        if (jsonNode.hasNonNull("watch")) {
            try {
                result.watch = WatchInfo.create(jsonNode.get("watch"));
            } catch (Exception e) {
                log.error("Error while parsing " + jsonNode.get("watch"), e);
            }
        }

        if (jsonNode.hasNonNull("trigger")) {
            try {
                result.triggerInfo = TriggerInfo.create(jsonNode.get("trigger"));
            } catch (Exception e) {
                log.error("Error while parsing " + jsonNode.get("trigger"), e);
            }
        }

        if (jsonNode.hasNonNull("execution_time")) {
            try {
                result.executionTime = parseJodaCompatibleZonedDateTime(jsonNode.get("execution_time").textValue());
            } catch (Exception e) {
                log.error("Error while parsing " + jsonNode.get("execution_time"), e);
            }
        }

        return result;
    }

    public static class TriggerInfo implements ToXContentObject {
        public final JodaCompatibleZonedDateTime triggeredTime;
        public final JodaCompatibleZonedDateTime scheduledTime;
        public final JodaCompatibleZonedDateTime previousScheduledTime;
        public final JodaCompatibleZonedDateTime nextScheduledTime;

        public TriggerInfo() {
            this.triggeredTime = null;
            this.scheduledTime = null;
            this.previousScheduledTime = null;
            this.nextScheduledTime = null;
        }

        public TriggerInfo(JodaCompatibleZonedDateTime triggeredTime, JodaCompatibleZonedDateTime scheduledTime,
                JodaCompatibleZonedDateTime previousScheduledTime, JodaCompatibleZonedDateTime nextScheduledTime) {
            this.triggeredTime = triggeredTime;
            this.scheduledTime = scheduledTime;
            this.previousScheduledTime = previousScheduledTime;
            this.nextScheduledTime = nextScheduledTime;
        }

        public TriggerInfo(Date triggeredTime, Date scheduledTime, Date previousScheduledTime, Date nextScheduledTime) {
            this.triggeredTime = toJoda(triggeredTime);
            this.scheduledTime = toJoda(scheduledTime);
            this.previousScheduledTime = toJoda(previousScheduledTime);
            this.nextScheduledTime = toJoda(nextScheduledTime);
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            builder.startObject();
            builder.field("triggered_time",
                    triggeredTime != null ? DateTimeFormatter.ISO_ZONED_DATE_TIME.format(triggeredTime.getZonedDateTime()) : null);
            builder.field("scheduled_time",
                    scheduledTime != null ? DateTimeFormatter.ISO_ZONED_DATE_TIME.format(scheduledTime.getZonedDateTime()) : null);
            builder.field("previous_scheduled_time",
                    previousScheduledTime != null ? DateTimeFormatter.ISO_ZONED_DATE_TIME.format(previousScheduledTime.getZonedDateTime()) : null);
            builder.field("next_scheduled_time",
                    nextScheduledTime != null ? DateTimeFormatter.ISO_ZONED_DATE_TIME.format(nextScheduledTime.getZonedDateTime()) : null);
            builder.endObject();
            return builder;
        }

        public Map<String, Object> toMap() {
            return ObjectTreeXContent.toMap(this);
        }

        public static TriggerInfo create(JsonNode jsonNode) {
            JodaCompatibleZonedDateTime triggeredTime = null;
            JodaCompatibleZonedDateTime scheduledTime = null;
            JodaCompatibleZonedDateTime previousScheduledTime = null;
            JodaCompatibleZonedDateTime nextScheduledTime = null;

            if (jsonNode.hasNonNull("triggered_time")) {
                triggeredTime = parseJodaCompatibleZonedDateTime(jsonNode.get("triggered_time").textValue());
            }
            if (jsonNode.hasNonNull("scheduled_time")) {
                scheduledTime = parseJodaCompatibleZonedDateTime(jsonNode.get("scheduled_time").textValue());
            }
            if (jsonNode.hasNonNull("previous_scheduled_time")) {
                previousScheduledTime = parseJodaCompatibleZonedDateTime(jsonNode.get("previous_scheduled_time").textValue());
            }
            if (jsonNode.hasNonNull("next_scheduled_time")) {
                nextScheduledTime = parseJodaCompatibleZonedDateTime(jsonNode.get("next_scheduled_time").textValue());
            }
            return new TriggerInfo(triggeredTime, scheduledTime, previousScheduledTime, nextScheduledTime);
        }

        public JodaCompatibleZonedDateTime getTriggeredTime() {
            return triggeredTime;
        }

        public JodaCompatibleZonedDateTime getScheduledTime() {
            return scheduledTime;
        }

        public JodaCompatibleZonedDateTime getPreviousScheduledTime() {
            return previousScheduledTime;
        }

        public JodaCompatibleZonedDateTime getNextScheduledTime() {
            return nextScheduledTime;
        }

        public JodaCompatibleZonedDateTime getTriggered_time() {
            return triggeredTime;
        }

        public JodaCompatibleZonedDateTime getScheduled_time() {
            return scheduledTime;
        }

        public JodaCompatibleZonedDateTime getPrevious_scheduled_time() {
            return previousScheduledTime;
        }

        public JodaCompatibleZonedDateTime getNext_scheduled_time() {
            return nextScheduledTime;
        }
    }

    public static class WatchInfo implements ToXContentObject {
        public final String id;
        public final String tenant;

        public WatchInfo(String id, String tenant) {
            this.id = id;
            this.tenant = tenant;
        }

        public String getId() {
            return id;
        }

        public String getTenant() {
            return tenant;
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            builder.startObject();
            builder.field("id", id);
            builder.field("tenant", tenant);
            builder.endObject();
            return builder;
        }

        public Map<String, Object> toMap() {
            return ObjectTreeXContent.toMap(this);
        }

        public static WatchInfo create(JsonNode jsonNode) {
            String id = null;
            String tenant = null;

            if (jsonNode.hasNonNull("id")) {
                id = jsonNode.get("id").textValue();
            }

            if (jsonNode.hasNonNull("tenant")) {
                tenant = jsonNode.get("tenant").textValue();
            }

            return new WatchInfo(id, tenant);
        }
    }

    private static JodaCompatibleZonedDateTime toJoda(Date date) {
        if (date == null) {
            return null;
        } else {
            return new JodaCompatibleZonedDateTime(date.toInstant(), ZoneOffset.UTC);
        }
    }

    static JodaCompatibleZonedDateTime parseJodaCompatibleZonedDateTime(String value) {
        ZonedDateTime dt = ZonedDateTime.parse(value);

        return new JodaCompatibleZonedDateTime(dt.toInstant(), dt.getZone());

    }

    public NestedValueMap getItem() {
        return item;
    }

    public void setItem(NestedValueMap item) {
        this.item = item;
    }

    public WatchInfo getWatch() {
        return watch;
    }

    public void setWatch(WatchInfo watch) {
        this.watch = watch;
    }
}
