package io.github.jody2905.logwarden.core.detect;

import io.github.jody2905.logwarden.core.Detection;
import io.github.jody2905.logwarden.core.Event;
import io.github.jody2905.logwarden.core.Severity;

import java.util.List;

/**
 * A detection rule. Rules see events one at a time, in time order, and keep whatever memory they need
 * (sliding windows, last-seen locations). They return a detection when something looks wrong.
 */
public interface Rule {

    String id();

    String name();

    /** What the rule looks for, shown on the Rules page. */
    String description();

    /** MITRE ATT&CK technique id, e.g. "T1110.001". */
    String mitre();

    Severity severity();

    List<Detection> onEvent(Event e);

    /** Forget everything (used when replaying history). */
    void reset();
}
