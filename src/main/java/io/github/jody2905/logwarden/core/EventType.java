package io.github.jody2905.logwarden.core;

/** What an event means, whatever log it came from. */
public enum EventType {
    LOGIN_SUCCESS("Login succeeded"),
    LOGIN_FAILURE("Login failed"),
    ACCOUNT_CREATED("Account created"),
    GROUP_MEMBER_ADDED("Added to group"),
    PRIVILEGE_USE("Admin rights used"),
    LOG_CLEARED("Audit log cleared"),
    HTTP_REQUEST("Web request"),
    CONNECTION_BLOCKED("Connection blocked"),
    CONNECTION_ALLOWED("Connection allowed"),
    OTHER("Other");

    private final String label;

    EventType(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }
}
