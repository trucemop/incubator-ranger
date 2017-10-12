/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.apache.ranger.plugin.audit;

import java.util.ArrayList;
import java.util.Collection;
import org.apache.ranger.audit.model.AuthzAuditEvent;

public class RangerAccumuloAuditHandler extends RangerDefaultAuditHandler {

    Collection<AuthzAuditEvent> auditEvents = new ArrayList<AuthzAuditEvent>();

    public RangerAccumuloAuditHandler() {
    }

    @Override
    public void logAuthzAudit(AuthzAuditEvent auditEvent) {
        auditEvents.add(auditEvent);
    }

    @Override
    public void logAuthzAudits(Collection<AuthzAuditEvent> auditEvents) {
        auditEvents.addAll(auditEvents);
    }

    public void flushAudit() {
        try {
            for (AuthzAuditEvent auditEvent : auditEvents) {
                super.logAuthzAudit(auditEvent);
            }
        } catch (Throwable t) {

        }
    }
}
