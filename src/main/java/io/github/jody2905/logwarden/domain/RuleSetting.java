package io.github.jody2905.logwarden.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** Whether a rule is switched on, so the choice survives restarts. */
@Entity
@Table(name = "rule_settings")
public class RuleSetting {

    @Id
    @Column(name = "rule_id")
    private String ruleId;
    @Column(nullable = false)
    private boolean enabled;

    protected RuleSetting() { }

    public RuleSetting(String ruleId, boolean enabled) {
        this.ruleId = ruleId;
        this.enabled = enabled;
    }

    public String getRuleId() { return ruleId; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
}
