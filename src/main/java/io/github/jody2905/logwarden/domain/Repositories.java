package io.github.jody2905.logwarden.domain;

import io.github.jody2905.logwarden.core.Severity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

/** Spring Data repositories, kept together because each is small. */
public final class Repositories {

    private Repositories() { }

    public interface Events extends JpaRepository<EventEntity, Long>, JpaSpecificationExecutor<EventEntity> {

        List<EventEntity> findByIdInOrderByTimeAsc(Collection<Long> ids);

        List<EventEntity> findByTimeAfterOrderByTimeAsc(Instant after);

        @Query("select max(e.time) from EventEntity e")
        Optional<Instant> latestTime();

        /** Newest log event, not counting LogWarden's own sign-in records. */
        @Query("select max(e.time) from EventEntity e where e.source <> 'logwarden'")
        Optional<Instant> latestLogTime();

        @Query("select e.source, count(e) from EventEntity e where e.time >= :from group by e.source")
        List<Object[]> countBySource(@Param("from") Instant from);

        @Query("select e.time from EventEntity e where e.time >= :from")
        List<Instant> timesSince(@Param("from") Instant from);

        @Query("select e.srcIp, count(e) from EventEntity e where e.time >= :from and e.srcIp is not null and e.type in "
                + "(io.github.jody2905.logwarden.core.EventType.LOGIN_FAILURE, io.github.jody2905.logwarden.core.EventType.CONNECTION_BLOCKED) "
                + "group by e.srcIp order by count(e) desc")
        List<Object[]> topNoisyIps(@Param("from") Instant from, Pageable page);

        @Modifying
        @Query("delete from EventEntity e where e.time < :before")
        int deleteOlderThan(@Param("before") Instant before);
    }

    public interface Alerts extends JpaRepository<AlertEntity, Long>, JpaSpecificationExecutor<AlertEntity> {

        Optional<AlertEntity> findFirstByRuleIdAndEntityOrderByLastSeenDesc(String ruleId, String entity);

        Page<AlertEntity> findAllByOrderByLastSeenDesc(Pageable page);

        long countByStatusIn(Collection<AlertEntity.Status> statuses);

        @Query("select a.severity, count(a) from AlertEntity a where a.status in :statuses group by a.severity")
        List<Object[]> countOpenBySeverity(@Param("statuses") Collection<AlertEntity.Status> statuses);

        @Query("select a.status, count(a) from AlertEntity a group by a.status")
        List<Object[]> countByStatus();

        @Query("select a.ruleId, count(a) from AlertEntity a group by a.ruleId order by count(a) desc")
        List<Object[]> countByRule();

        List<AlertEntity> findByStatusIn(Collection<AlertEntity.Status> statuses);

        long countBySeverityAndStatusIn(Severity severity, Collection<AlertEntity.Status> statuses);
    }

    public interface Notes extends JpaRepository<AlertNote, Long> {
        List<AlertNote> findByAlertIdOrderByCreatedAtAsc(Long alertId);
    }

    public interface RuleSettings extends JpaRepository<RuleSetting, String> { }
}
