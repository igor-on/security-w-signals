package org.opensearch.security.signals.watch.state;

import java.util.Map;

import org.opensearch.core.action.ActionListener;

public interface WatchStateWriter<Response> {
    void put(String watchId, WatchState watchState);

    void put(String watchId, WatchState watchState, ActionListener<Response> actionListener);

    void putAll(Map<String, WatchState> idToStateMap);
}
