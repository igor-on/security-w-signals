package org.opensearch.security.searchsupport.jobs.config.schedule;

import org.quartz.JobKey;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.opensearch.security.codova.validation.ConfigValidationException;

public interface ScheduleFactory<X extends Schedule> {
    public X create(JobKey jobKey, ObjectNode objectNode) throws ConfigValidationException;
}
