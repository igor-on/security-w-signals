package org.opensearch.security.signals.watch.result;

public interface WatchLogWriter {
    void put(WatchLog watchLog);
}
