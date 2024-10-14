package org.opensearch.security.searchsupport.jobs.config.schedule;

import java.util.List;

import org.opensearch.core.xcontent.ToXContentObject;
import org.quartz.Trigger;

public interface Schedule extends ToXContentObject {
    List<Trigger> getTriggers();
}
