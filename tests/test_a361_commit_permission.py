"""Real SQLite two-order commit/deadline controls with bounded gate cleanup."""
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest import mock

from kiwi_catalog.core.errors import ConflictError
from kiwi_catalog.db.session import open_connection
from kiwi_catalog.services import agent_verification as av
from kiwi_catalog.services.verification_stages import VerificationResult


class ControlledService:
    def __init__(self,h,agent_gate=None,commit_gate=None,commit_error=False):
        self.h=h;self.verify_gate=agent_gate;self.commit_gate=commit_gate;self.commit_error=commit_error
        self.conn=sqlite3.connect(h.business);self.calls=0;self.closed=threading.Event()
        self.verifying=threading.Event();self.committing=threading.Event();self.close_flags=[]
    def verify(self,agent,**kwargs):
        self.conn.execute('insert into effects(agent) values (?)',(agent,));self.verifying.set()
        if self.verify_gate is not None:self.verify_gate.wait(4)
        return VerificationResult(catalog_agent_id=agent,previous_status='unverified',status='verified',stages=())
    refresh=verify
    mark_stale=verify
    suspend=verify
    def commit(self):
        self.calls+=1;self.committing.set()
        if self.commit_gate is not None:self.commit_gate.wait(4)
        if self.commit_error:raise sqlite3.OperationalError('uncertain commit acknowledgement')
        self.conn.commit()
    def close(self,commit=True):
        self.close_flags.append(commit)
        try:
            if commit:self.conn.commit()
        finally:self.conn.close();self.closed.set()


class Harness:
    def __init__(self,test,same_db=False):
        temp=tempfile.TemporaryDirectory(prefix='a361-commit-');test.addCleanup(temp.cleanup)
        self.ledger=temp.name+'/ledger.sqlite';self.business=self.ledger if same_db else temp.name+'/business.sqlite'
        c=open_connection(self.ledger);c.close()
        c=sqlite3.connect(self.business);c.execute('create table effects(agent text)');c.commit();c.close()
        self.services=[];self.gates=[];self.queues=[]
        test.addCleanup(self.cleanup)
    def factory(self,verify_gate=None,commit_gate=None,commit_error=False):
        if verify_gate:self.gates.append(verify_gate)
        if commit_gate:self.gates.append(commit_gate)
        def make():
            s=ControlledService(self,verify_gate,commit_gate,commit_error);self.services.append(s);return s
        return make
    def queue(self,factory,concurrency=1):
        q=av.VerificationQueue(service_factory=factory,config=av.VerificationQueueConfig(max_pending=10,concurrency=concurrency,task_timeout_seconds=.12),db_path=self.ledger);self.queues.append(q);return q
    def rows(self):
        c=sqlite3.connect(self.business)
        try:return c.execute('select count(*) from effects').fetchone()[0]
        finally:c.close()
    def ledger_row(self,tid):
        c=sqlite3.connect(self.ledger);c.row_factory=sqlite3.Row
        try:return dict(c.execute('select * from verification_queue_tasks where task_id=?',(tid,)).fetchone())
        finally:c.close()
    def cleanup(self):
        for gate in self.gates:gate.set()
        for s in self.services:s.closed.wait(2)
        for q in self.queues:q.shutdown(wait=True,timeout=1)


class CommitPermissionTest(unittest.TestCase):
    def wait_for(self,predicate,seconds=2):
        end=time.monotonic()+seconds
        while not predicate() and time.monotonic()<end:time.sleep(.002)
        self.assertTrue(predicate(),'fixture barrier not reached')

    def test_timeout_wins_zero_commit_and_close_cannot_commit(self):
        h=Harness(self);gate=threading.Event();q=h.queue(h.factory(verify_gate=gate));r=q.enqueue('a')
        self.wait_for(lambda:h.services and h.services[0].verifying.is_set())
        out=q.wait(r.task_id,timeout=1);self.assertEqual(out.status,'timeout')
        gate.set();self.assertTrue(h.services[0].closed.wait(1))
        self.assertEqual(h.services[0].calls,0);self.assertEqual(h.services[0].close_flags,[False]);self.assertEqual(h.rows(),0)
        self.assertEqual(h.ledger_row(r.task_id)['status'],'timeout')

    def test_commit_wins_returns_unknown_without_waiting_for_commit_io(self):
        h=Harness(self);gate=threading.Event();q=h.queue(h.factory(commit_gate=gate));r=q.enqueue('a')
        self.wait_for(lambda:h.services and h.services[0].committing.is_set())
        started=time.monotonic();out=q.wait(r.task_id,timeout=1)
        self.assertEqual(out.status,'unknown');self.assertLess(time.monotonic()-started,.5)
        self.assertEqual(h.ledger_row(r.task_id)['status'],'running')
        with self.assertRaises(ConflictError):q.enqueue('a',kind='refresh')
        gate.set();self.assertTrue(h.services[0].closed.wait(1));self.assertEqual(h.rows(),1)
        self.assertEqual(q.wait(r.task_id).status,'unknown');self.assertEqual(h.services[0].close_flags,[False])
        self.assertEqual(h.ledger_row(r.task_id)['status'],'running')

    def test_fast_commit_completes_and_closes_without_second_commit(self):
        h=Harness(self);q=h.queue(h.factory());out=q.enqueue('a',wait=True,timeout=1)
        self.assertEqual(out.status,'completed');self.assertEqual(h.rows(),1)
        self.assertEqual(h.services[0].calls,1);self.assertEqual(h.services[0].close_flags,[False])
        self.assertEqual(h.ledger_row(out.task_id)['status'],'completed')

    def test_commit_exception_is_unknown_not_known_failure(self):
        h=Harness(self);q=h.queue(h.factory(commit_error=True));out=q.enqueue('a',wait=True,timeout=1)
        self.assertEqual(out.status,'unknown');self.assertIn('commit',out.error)
        self.assertEqual(h.rows(),0);self.assertEqual(h.services[0].close_flags,[False])
        with self.assertRaises(ConflictError):q.enqueue('a',kind='suspend')

    def test_same_db_unknown_marker_busy_keeps_running_and_blocks_restart(self):
        h=Harness(self,same_db=True);gate=threading.Event();q=h.queue(h.factory(commit_gate=gate));r=q.enqueue('a')
        self.wait_for(lambda:h.services and h.services[0].committing.is_set())
        started=time.monotonic();out=q.wait(r.task_id,timeout=1)
        self.assertEqual(out.status,'unknown');self.assertLess(time.monotonic()-started,.5)
        self.assertIn('persist',out.error.lower());self.assertEqual(h.ledger_row(r.task_id)['status'],'running')
        gate.set();self.assertTrue(h.services[0].closed.wait(1));q.shutdown()
        rebuilt=h.queue(h.factory());self.assertEqual(rebuilt._recovered_tasks,[])
        self.assertEqual(rebuilt.wait(r.task_id,timeout=.01).status,'unknown')
        with self.assertRaises(ConflictError):rebuilt.enqueue('a',kind='refresh')
        self.assertEqual(len(h.services),1);self.assertEqual(h.rows(),1)

    def test_runner_threads_stay_bounded_while_commit_is_stuck(self):
        h=Harness(self);gate=threading.Event();q=h.queue(h.factory(commit_gate=gate));first=q.enqueue('a')
        self.wait_for(lambda:h.services and h.services[0].committing.is_set());self.assertEqual(q.wait(first.task_id,timeout=1).status,'unknown')
        for agent in ('b','c','d'):
            out=q.enqueue(agent,wait=True,timeout=1);self.assertEqual(out.status,'timeout')
        self.assertEqual(len(h.services),1)
        q.shutdown();self.assertFalse(any(w.is_alive() for w in q._workers))
        gate.set();self.assertTrue(h.services[0].closed.wait(1))

    def test_restart_preserves_running_unknown_and_recovers_only_safe_pending(self):
        h=Harness(self);c=sqlite3.connect(h.ledger)
        for tid,agent,status in [('old-running','a','running'),('pending-blocked','a','pending'),('pending-safe','b','pending')]:
            c.execute('insert into verification_queue_tasks(task_id,catalog_agent_id,kind,actor,status,enqueued_at,created_at,updated_at) values (?,?,?,?,?,?,?,?)',(tid,agent,'verify','fixture',status,1,'c','u'))
        c.commit();c.close();q=h.queue(h.factory())
        self.assertEqual(q.wait('old-running',timeout=1).status,'unknown')
        self.assertEqual(q.wait('pending-blocked',timeout=1).status,'unknown')
        self.assertEqual(q.wait('pending-safe',timeout=1).status,'completed')
        self.assertEqual(h.rows(),1);self.assertEqual(len(h.services),1)
        with self.assertRaises(ConflictError):q.enqueue('a',kind='refresh')
        # Unresolved running rows are never terminal-GC candidates.
        from kiwi_catalog.services.verification_queue_ledger import cleanup_terminal_tasks
        c=sqlite3.connect(h.ledger);cleanup_terminal_tasks(c,time.time()+100*86400);c.commit();c.close()
        self.assertEqual(h.ledger_row('old-running')['status'],'running')
        self.assertEqual(h.ledger_row('pending-blocked')['status'],'running')

    def test_admitted_deferred_follower_becomes_unknown_without_effect(self):
        h=Harness(self);gate=threading.Event();q=h.queue(h.factory(commit_gate=gate),concurrency=2)
        first=q.enqueue('a');self.wait_for(lambda:h.services and h.services[0].committing.is_set())
        second=q.enqueue('a',kind='refresh');self.wait_for(lambda:bool(q._agent_deferred.get('a')))
        self.assertEqual(q.wait(first.task_id,timeout=1).status,'unknown')
        blocked=q.wait(second.task_id,timeout=1)
        self.assertEqual((blocked.task_id,blocked.kind,blocked.status),(second.task_id,'refresh','unknown'))
        self.assertEqual(len(h.services),1);self.assertEqual(h.rows(),0)
        self.assertEqual(h.ledger_row(second.task_id)['status'],'running')
        q.shutdown();self.assertFalse(any(w.is_alive() for w in q._workers));self.assertEqual(q._agent_preclaimed,{})
        gate.set();self.assertTrue(h.services[0].closed.wait(1));self.assertEqual(h.rows(),1)
        self.assertEqual(q.wait(second.task_id).status,'unknown')

    def test_enqueue_persisted_before_unknown_cannot_slip_into_execution(self):
        h=Harness(self);gate=threading.Event();q=h.queue(h.factory(commit_gate=gate),concurrency=2)
        first=q.enqueue('a');self.wait_for(lambda:h.services and h.services[0].committing.is_set())
        inserted=threading.Event();admit=threading.Event();errors=[]
        original=q._persist_insert
        def pause_insert(task):
            original(task);inserted.set()
            if not admit.wait(2):raise AssertionError('admission fixture barrier not released')
        def enqueue_second():
            try:q.enqueue('a',kind='refresh')
            except Exception as exc:errors.append(exc)
        with mock.patch.object(q,'_persist_insert',side_effect=pause_insert):
            thread=threading.Thread(target=enqueue_second);thread.start()
            try:
                self.assertTrue(inserted.wait(1));self.assertEqual(q.wait(first.task_id,timeout=1).status,'unknown')
            finally:admit.set();thread.join(2)
        self.assertFalse(thread.is_alive());self.assertEqual(len(errors),1);self.assertIsInstance(errors[0],ConflictError)
        blocked=[x for tid,x in q._results.items() if tid!=first.task_id]
        self.assertEqual(len(blocked),1);self.assertEqual((blocked[0].kind,blocked[0].status),('refresh','unknown'))
        self.assertEqual(len(h.services),1);self.assertEqual(h.ledger_row(blocked[0].task_id)['status'],'running')
        gate.set();self.assertTrue(h.services[0].closed.wait(1));q.shutdown()
        self.assertEqual(set(q._tasks),set(q._results))

    def test_register_preserves_committed_registration_when_unknown_blocks_enqueue(self):
        from kiwi_catalog.api.app import handle_request
        h=Harness(self)
        with mock.patch.dict('os.environ',{'KIWI_CATALOG_ADMIN_TOKEN':'a361-fake-admin','KIWI_CATALOG_OWNER_TOKEN_SECRET':'a361-fake-owner'}),mock.patch(
            'kiwi_catalog.api.handlers.agent_catalog._enqueue_verification',side_effect=av.VerificationQueueOutcomeUnknownError('prior outcome unknown')):
            status,payload=handle_request(h.ledger,'POST','/v1/agent-catalog/agents/register',{'domain':'register-a361.example','display_name':'synthetic','admin_token':'a361-fake-admin'})
        self.assertEqual(status,200,payload);self.assertFalse(payload.get('verification_enqueued',True));self.assertIn('reconciliation',payload['queue_reason'])
        c=sqlite3.connect(h.ledger)
        try:self.assertEqual(c.execute("select count(*) from catalog_agents where canonical_domain='register-a361.example'").fetchone()[0],1)
        finally:c.close()

    def seed_agent(self,h):
        from kiwi_catalog.agent_catalog.sqlite_repository import new_catalog_agent_id,upsert_catalog_agent
        from kiwi_catalog.db.session import db_session
        agent=new_catalog_agent_id()
        with db_session(h.ledger) as c:
            upsert_catalog_agent(c,catalog_agent_id=agent,merchant_id='',canonical_domain='moderation-a361.example',source_type='admin_curated',lifecycle_status='active')
        return agent

    def test_reinstate_preserves_governance_commit_when_unknown_blocks_enqueue(self):
        from kiwi_catalog.api.app import handle_request
        h=Harness(self);agent=self.seed_agent(h);c=sqlite3.connect(h.ledger);c.execute("update catalog_agents set administrative_state='suspended' where catalog_agent_id=?",(agent,));c.commit();c.close()
        with mock.patch.dict('os.environ',{'KIWI_CATALOG_ADMIN_TOKEN':'a361-fake-admin','KIWI_CATALOG_OWNER_TOKEN_SECRET':'a361-fake-owner'}),mock.patch(
            'kiwi_catalog.api.handlers.agent_catalog._enqueue_verification',side_effect=av.VerificationQueueOutcomeUnknownError('prior outcome unknown')):
            status,payload=handle_request(h.ledger,'POST',f'/v1/agent-catalog/agents/{agent}/reinstate',{'admin_token':'a361-fake-admin','reason':'synthetic'})
        self.assertEqual(status,200,payload);self.assertFalse(payload.get('verify_enqueued',True));self.assertIn('reconciliation',payload['queue_reason'])
        c=sqlite3.connect(h.ledger)
        try:self.assertEqual(c.execute('select administrative_state from catalog_agents where catalog_agent_id=?',(agent,)).fetchone()[0],'active')
        finally:c.close()

    def test_refresh_unknown_never_replays_a_false_enqueue_success(self):
        from kiwi_catalog.api.app import handle_request
        h=Harness(self);agent=self.seed_agent(h);body={'admin_token':'a361-fake-admin','idempotency_key':'a361-refresh-unknown'}
        with mock.patch.dict('os.environ',{'KIWI_CATALOG_ADMIN_TOKEN':'a361-fake-admin','KIWI_CATALOG_OWNER_TOKEN_SECRET':'a361-fake-owner'}),mock.patch(
            'kiwi_catalog.api.handlers.agent_catalog._enqueue_verification',side_effect=av.VerificationQueueOutcomeUnknownError('prior outcome unknown')) as enqueue:
            responses=[]
            for _ in range(2):
                status,payload=handle_request(h.ledger,'POST',f'/v1/agent-catalog/agents/{agent}/refresh',body)
                self.assertEqual(status,200,payload)
                self.assertIs(payload.get('refresh_enqueued'),False,'unknown cannot replay as successfully enqueued')
                self.assertIn('reconciliation',payload['queue_reason'])
                responses.append(payload)
            self.assertEqual(enqueue.call_count,1)
            self.assertFalse(responses[0]['idempotent']);self.assertTrue(responses[1]['idempotent'])
            first={k:v for k,v in responses[0].items() if k!='idempotent'}
            replay={k:v for k,v in responses[1].items() if k!='idempotent'}
            self.assertEqual(first,replay)
            c=sqlite3.connect(h.ledger)
            try:
                raw=c.execute('select response_json from agent_catalog_write_idempotency where endpoint=? and idempotency_key=?',
                    ('POST /v1/agent-catalog/agents/{id}/refresh','a361-refresh-unknown')).fetchone()
                # Verify the real row, without depending on an endpoint-label fixture.
                if raw is None:
                    raw=c.execute('select response_json from agent_catalog_write_idempotency where idempotency_key=?',('a361-refresh-unknown',)).fetchone()
                import json
                cached=json.loads(raw[0]);self.assertEqual(cached,responses[0])
            finally:c.close()
