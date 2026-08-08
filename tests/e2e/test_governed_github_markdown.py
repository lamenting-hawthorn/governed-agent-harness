"""Real-PostgreSQL proof for the bounded pinned GitHub Markdown slice."""

from __future__ import annotations

import copy
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from threading import Barrier

import pytest

from governed_agent_harness.contracts import apply_object_digest, sha256_digest
from governed_agent_harness.contracts.positive_fixtures import build_positive_records
from governed_agent_harness.knowledge import (
    GithubMarkdownSourceError,
    PinnedGithubMarkdown,
    PostgresGithubMarkdownAuthority,
    PostgresGithubMarkdownReader,
)
from governed_agent_harness.persistence import PostgresDurableEffectStore


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _live_actor(postgres_connections):
    """Bind test logins to a canonical actor valid at the real PostgreSQL clock."""

    actor = copy.deepcopy(build_positive_records()["actor_context"])
    current = datetime.now(timezone.utc)
    actor["auth"]["verified_at"] = _timestamp(current.replace(microsecond=0))
    actor["issued_at"] = _timestamp(current)
    actor["expires_at"] = _timestamp(current.replace(microsecond=0) + timedelta(hours=1))
    PostgresDurableEffectStore.provision_principal(
        admin_connect=postgres_connections["admin"],
        database_roles=("gah_app", "gah_writer"),
        actor_context=actor,
    )
    return actor


def _ids():
    state = [0xC000]

    def next_id() -> str:
        state[0] += 1
        return f"018f0000-0000-7000-8000-{state[0]:012x}"

    return next_id


def _source(
    *,
    commit_sha: str = "a" * 40,
    content: str | None = None,
    retention_expires_at: str | None = None,
) -> PinnedGithubMarkdown:
    return PinnedGithubMarkdown(
        repository="acme/brain",
        commit_sha=commit_sha,
        path="docs/roadmap.md",
        content=content
        or "# Roadmap\n\nThe governed knowledge path returns cited untrusted context.\n",
        classification="internal",
        retention_expires_at=retention_expires_at
        or _timestamp(datetime.now(timezone.utc) + timedelta(days=30)),
    )


def _policy(actor, *, operation_id: str, operation_digest: str, decision_id: str):
    policy = copy.deepcopy(build_positive_records()["policy_decision"])
    policy.update(
        {
            "tenant_id": actor["tenant_id"],
            "decision_id": decision_id,
            "request_id": operation_id,
            "request_digest": operation_digest,
            "decision": "authorize",
            "rule_refs": ["knowledge.github_import.v1"],
            "constraints": [],
            "isolation_profile": "no_effect",
            "decided_at": _timestamp(datetime.now(timezone.utc)),
        }
    )
    return apply_object_digest(policy)


def _authority(postgres_connections):
    return PostgresGithubMarkdownAuthority(
        privileged_connect=postgres_connections["writer"],
        clock=lambda: datetime.now(timezone.utc),
        ids=_ids(),
    )


def _import_payload(
    *,
    actor: dict[str, object],
    operation_id: str,
    run_id: str,
    source: PinnedGithubMarkdown,
    policy: dict[str, object],
) -> dict[str, object]:
    return {
        "operation_id": operation_id,
        "operation_digest": source.operation_digest(operation_id),
        "run_id": run_id,
        "source": source.to_dict(),
        "policy_decision": policy,
    }


def _evidence_source_metadata(source: PinnedGithubMarkdown) -> dict[str, str]:
    return {key: value for key, value in source.to_dict().items() if key != "content"}


def _counts(postgres_connections):
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT "
            "(SELECT count(*) FROM gah_github_markdown_sources), "
            "(SELECT count(*) FROM gah_github_markdown_revisions), "
            "(SELECT count(*) FROM gah_evidence_events WHERE "
            "envelope_json #>> '{draft,event_kind}' LIKE 'knowledge.github_markdown_%')"
        )
        return cursor.fetchone()


def _run_head_count(postgres_connections, *, actor: dict[str, object], run_id: str) -> int:
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT count(*) FROM gah_run_heads WHERE tenant_id = %s AND actor_id = %s AND run_id = %s",
            (actor["tenant_id"], actor["actor_id"], run_id),
        )
        return cursor.fetchone()[0]


def _operation_count(postgres_connections) -> int:
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT count(*) FROM gah_github_markdown_operations")
        return cursor.fetchone()[0]


def _runtime_events(postgres_connections, *, actor: dict[str, object], run_id: str):
    with postgres_connections["app"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT gah_runtime_read(%s,%s::jsonb,%s::jsonb)",
            ("events", json.dumps(actor), json.dumps({"run_id": run_id})),
        )
        return cursor.fetchone()[0]


def test_pinned_fetch_accepts_only_a_full_commit_and_exposes_no_credential_parameter():
    calls: list[tuple[str, str, str]] = []

    class RecordingClient:
        def read_markdown(self, *, repository: str, commit_sha: str, path: str) -> str:
            calls.append((repository, commit_sha, path))
            return "# Pinned\n"

    client = RecordingClient()
    retention_expires_at = _timestamp(datetime.now(timezone.utc) + timedelta(days=30))
    fetched = PinnedGithubMarkdown.fetch(
        client=client,
        repository="acme/brain",
        commit_sha="c" * 40,
        path="docs/pinned.md",
        classification="internal",
        retention_expires_at=retention_expires_at,
    )
    assert fetched.content == "# Pinned\n"
    assert calls == [("acme/brain", "c" * 40, "docs/pinned.md")]
    with pytest.raises(GithubMarkdownSourceError, match="full lowercase commit SHA"):
        PinnedGithubMarkdown.fetch(
            client=client,
            repository="acme/brain",
            commit_sha="main",
            path="docs/pinned.md",
            classification="internal",
            retention_expires_at=retention_expires_at,
        )
    assert calls == [("acme/brain", "c" * 40, "docs/pinned.md")]


@pytest.mark.parametrize(
    ("classification", "retention_expires_at", "message"),
    (
        ("unexpected", "2030-01-01T00:00:00.000Z", "classification is unsupported"),
        (None, "2030-01-01T00:00:00.000Z", "classification is unsupported"),
        ("internal", "2030-02-30T00:00:00.000Z", "retention expiry is malformed"),
        ("internal", "2000-01-01T00:00:00.000Z", "retention expiry is expired"),
    ),
)
def test_pinned_fetch_rejects_invalid_metadata_before_reading_the_client(
    classification: object, retention_expires_at: str, message: str
):
    calls: list[tuple[str, str, str]] = []

    class RecordingClient:
        def read_markdown(self, *, repository: str, commit_sha: str, path: str) -> str:
            calls.append((repository, commit_sha, path))
            return "# Pinned\n"

    with pytest.raises(GithubMarkdownSourceError, match=message):
        PinnedGithubMarkdown.fetch(
            client=RecordingClient(),
            repository="acme/brain",
            commit_sha="c" * 40,
            path="docs/pinned.md",
            classification=classification,  # type: ignore[arg-type]
            retention_expires_at=retention_expires_at,
        )
    assert calls == []


def test_pinned_fetch_rejects_retention_deadline_equal_to_the_local_clock_before_reading():
    calls: list[tuple[str, str, str]] = []

    class RecordingClient:
        def read_markdown(self, *, repository: str, commit_sha: str, path: str) -> str:
            calls.append((repository, commit_sha, path))
            return "# Pinned\n"

    with pytest.raises(GithubMarkdownSourceError, match="retention expiry is expired"):
        PinnedGithubMarkdown.fetch(
            client=RecordingClient(),
            repository="acme/brain",
            commit_sha="c" * 40,
            path="docs/pinned.md",
            classification="internal",
            retention_expires_at=_timestamp(datetime.now(timezone.utc)),
        )
    assert calls == []


@pytest.mark.parametrize(
    "credential",
    (
        "".join(("xox", "b-", "123456789012-abcdefghijklmnopqrstuvwxyz")),
        "".join(("sk", "_live_", "abcdefghijklmnopqrstuvwxyz0123456789")),
        "api_key=abcdefghijklmnopqrstuvwxyz0123456789",
        '{"password":"supersecret"}',
        'password = "supersecret"',
        'authorization = "Bearer abcdefghijklmnop"',
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhY3RvciJ9.c2lnbmF0dXJlMTIzNDU2Nzg5",
    ),
)
def test_pinned_source_rejects_common_credential_material(credential: str):
    with pytest.raises(GithubMarkdownSourceError, match="credential material"):
        _source(content=f"credential {credential}\n").validate()


def test_import_retrieve_revision_replay_and_read_only_mcp_shape(postgres_connections):
    actor = _live_actor(postgres_connections)
    with postgres_connections["writer"]() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT session_user, current_user")
        assert cursor.fetchone() == ("gah_writer", "gah_writer")
    source = _source()
    operation_id = "018f0000-0000-7000-8000-00000000c001"
    policy = _policy(
        actor,
        operation_id=operation_id,
        operation_digest=source.operation_digest(operation_id),
        decision_id="018f0000-0000-7000-8000-00000000c002",
    )
    authority = _authority(postgres_connections)
    imported = authority.import_markdown(
        actor_context=actor,
        operation_id=operation_id,
        run_id=actor["session_id"],
        source=source,
        policy_decision=policy,
    )
    assert imported.replayed is False
    assert imported.result.source_identity == "github://acme/brain/docs/roadmap.md"
    assert imported.result.revision_uri.endswith(f"/{source.commit_sha}/docs/roadmap.md")
    assert _counts(postgres_connections) == (1, 1, 1)

    replayed = authority.import_markdown(
        actor_context=actor,
        operation_id=operation_id,
        run_id=actor["session_id"],
        source=source,
        policy_decision=policy,
    )
    assert replayed.replayed is True
    assert replayed.result == imported.result
    assert _counts(postgres_connections) == (1, 1, 1)

    results = PostgresGithubMarkdownReader(runtime_connect=postgres_connections["app"]).retrieve(
        actor_context=actor, query="cited untrusted"
    )
    assert results == (imported.result,)
    assert results[0].is_untrusted_context is True
    resource = results[0].as_read_only_mcp_resource()
    assert resource["mimeType"] == "text/markdown"
    assert resource["metadata"]["read_only"] is True
    assert resource["metadata"]["untrusted_context"] is True
    assert resource["metadata"]["citation"] == dict(results[0].citation)
    events = _runtime_events(postgres_connections, actor=actor, run_id=actor["session_id"])
    assert source.content not in json.dumps(events)
    assert events[0]["draft"]["inline_payload"]["source"] == _evidence_source_metadata(source)


def test_import_returns_one_cited_result_when_retention_expires_during_the_statement(
    postgres_connections,
):
    """A statement-stable expiry check cannot commit an import then report it malformed."""

    actor = _live_actor(postgres_connections)
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "CREATE FUNCTION public.gah_test_delay_github_markdown_revision_insert() "
            "RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS "
            "$$ BEGIN PERFORM pg_catalog.pg_sleep(GREATEST(0::double precision, "
            "EXTRACT(EPOCH FROM (NEW.retention_expires_at + interval '100 milliseconds' "
            "- pg_catalog.clock_timestamp()))::double precision)); RETURN NEW; END $$"
        )
        cursor.execute(
            "CREATE TRIGGER gah_test_delay_github_markdown_revision_insert "
            "BEFORE INSERT ON public.gah_github_markdown_revisions "
            "FOR EACH ROW EXECUTE FUNCTION "
            "public.gah_test_delay_github_markdown_revision_insert()"
        )
        cursor.execute("SELECT pg_catalog.clock_timestamp()")
        retention_expires_at = _timestamp(cursor.fetchone()[0] + timedelta(seconds=2))

    try:
        source = _source(retention_expires_at=retention_expires_at)
        operation_id = "018f0000-0000-7000-8000-00000000c009"
        imported = _authority(postgres_connections).import_markdown(
            actor_context=actor,
            operation_id=operation_id,
            run_id=actor["session_id"],
            source=source,
            policy_decision=_policy(
                actor,
                operation_id=operation_id,
                operation_digest=source.operation_digest(operation_id),
                decision_id="018f0000-0000-7000-8000-00000000c010",
            ),
        )
        assert imported.replayed is False
        assert imported.result.content == source.content
        assert _counts(postgres_connections) == (1, 1, 1)
        with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_catalog.clock_timestamp() > %s::timestamptz",
                (retention_expires_at,),
            )
            assert cursor.fetchone()[0] is True
        assert (
            PostgresGithubMarkdownReader(runtime_connect=postgres_connections["app"]).retrieve(
                actor_context=actor, query="cited untrusted"
            )
            == ()
        )
    finally:
        with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
            cursor.execute(
                "DROP TRIGGER IF EXISTS gah_test_delay_github_markdown_revision_insert "
                "ON public.gah_github_markdown_revisions"
            )
            cursor.execute(
                "DROP FUNCTION IF EXISTS public.gah_test_delay_github_markdown_revision_insert()"
            )


def test_changed_pinned_commit_is_immutable_revision_and_revocation_hides_all_versions(
    postgres_connections,
):
    actor = _live_actor(postgres_connections)
    first = _source()
    second = _source(
        commit_sha="b" * 40,
        content="# Roadmap\n\nA later immutable revision retains its own citation.\n",
    )
    authority = _authority(postgres_connections)
    for operation_id, decision_id, source in (
        (
            "018f0000-0000-7000-8000-00000000c011",
            "018f0000-0000-7000-8000-00000000c012",
            first,
        ),
        (
            "018f0000-0000-7000-8000-00000000c013",
            "018f0000-0000-7000-8000-00000000c014",
            second,
        ),
    ):
        authority.import_markdown(
            actor_context=actor,
            operation_id=operation_id,
            run_id=actor["session_id"],
            source=source,
            policy_decision=_policy(
                actor,
                operation_id=operation_id,
                operation_digest=source.operation_digest(operation_id),
                decision_id=decision_id,
            ),
        )
    assert _counts(postgres_connections) == (1, 2, 2)
    reader = PostgresGithubMarkdownReader(runtime_connect=postgres_connections["app"])
    assert {item.commit_sha for item in reader.retrieve(actor_context=actor, query="Roadmap")} == {
        first.commit_sha,
        second.commit_sha,
    }

    revoke_operation = "018f0000-0000-7000-8000-00000000c015"
    assert (
        authority.revoke_source(
            actor_context=actor,
            operation_id=revoke_operation,
            run_id=actor["session_id"],
            source_identity=first.source_identity,
            policy_decision=_policy(
                actor,
                operation_id=revoke_operation,
                operation_digest=sha256_digest(
                    {"operation_id": revoke_operation, "source_identity": first.source_identity}
                ),
                decision_id="018f0000-0000-7000-8000-00000000c016",
            ),
        )
        is True
    )
    assert reader.retrieve(actor_context=actor, query="citation") == ()
    assert _counts(postgres_connections) == (1, 2, 3)

    reimport_operation = "018f0000-0000-7000-8000-00000000c017"
    with pytest.raises(Exception, match="revoked"):
        authority.import_markdown(
            actor_context=actor,
            operation_id=reimport_operation,
            run_id=actor["session_id"],
            source=first,
            policy_decision=_policy(
                actor,
                operation_id=reimport_operation,
                operation_digest=first.operation_digest(reimport_operation),
                decision_id="018f0000-0000-7000-8000-00000000c018",
            ),
        )
    assert _counts(postgres_connections) == (1, 2, 3)


def test_replay_requires_the_full_import_binding_and_expired_revisions_never_return(
    postgres_connections,
):
    actor = _live_actor(postgres_connections)
    authority = _authority(postgres_connections)
    source = _source()
    operation_id = "018f0000-0000-7000-8000-00000000c031"
    policy = _policy(
        actor,
        operation_id=operation_id,
        operation_digest=source.operation_digest(operation_id),
        decision_id="018f0000-0000-7000-8000-00000000c032",
    )
    authority.import_markdown(
        actor_context=actor,
        operation_id=operation_id,
        run_id=actor["session_id"],
        source=source,
        policy_decision=policy,
    )
    before = _counts(postgres_connections)

    changed_operation = "018f0000-0000-7000-8000-00000000c033"
    changed_run = "018f0000-0000-7000-8000-00000000c035"
    changed_policy = _policy(
        actor,
        operation_id=operation_id,
        operation_digest=source.operation_digest(operation_id),
        decision_id="018f0000-0000-7000-8000-00000000c036",
    )
    attempts = (
        (
            changed_operation,
            actor["session_id"],
            source,
            _policy(
                actor,
                operation_id=changed_operation,
                operation_digest=source.operation_digest(changed_operation),
                decision_id="018f0000-0000-7000-8000-00000000c034",
            ),
            "binding conflicts",
        ),
        (operation_id, changed_run, source, policy, "operation conflicts"),
        (operation_id, actor["session_id"], source, changed_policy, "operation conflicts"),
        (
            "018f0000-0000-7000-8000-00000000c037",
            actor["session_id"],
            replace(source, classification="restricted"),
            None,
            "binding conflicts",
        ),
        (
            "018f0000-0000-7000-8000-00000000c039",
            actor["session_id"],
            replace(
                source,
                retention_expires_at=_timestamp(datetime.now(timezone.utc) + timedelta(days=60)),
            ),
            None,
            "binding conflicts",
        ),
        (
            "018f0000-0000-7000-8000-00000000c041",
            actor["session_id"],
            replace(
                source, content="# Roadmap\n\nThe same commit cannot name different content.\n"
            ),
            None,
            "commit conflicts",
        ),
    )
    for attempted_operation, attempted_run, attempted_source, attempted_policy, error in attempts:
        resolved_policy = attempted_policy or _policy(
            actor,
            operation_id=attempted_operation,
            operation_digest=attempted_source.operation_digest(attempted_operation),
            decision_id={
                "018f0000-0000-7000-8000-00000000c037": "018f0000-0000-7000-8000-00000000c038",
                "018f0000-0000-7000-8000-00000000c039": "018f0000-0000-7000-8000-00000000c040",
                "018f0000-0000-7000-8000-00000000c041": "018f0000-0000-7000-8000-00000000c042",
            }[attempted_operation],
        )
        with pytest.raises(Exception, match=error):
            authority.import_markdown(
                actor_context=actor,
                operation_id=attempted_operation,
                run_id=attempted_run,
                source=attempted_source,
                policy_decision=resolved_policy,
            )
        assert _counts(postgres_connections) == before

    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "UPDATE gah_github_markdown_revisions "
            "SET retention_expires_at = clock_timestamp() - interval '1 second'"
        )
    reader = PostgresGithubMarkdownReader(runtime_connect=postgres_connections["app"])
    assert reader.retrieve(actor_context=actor, query="Roadmap") == ()
    assert source.content not in json.dumps(
        _runtime_events(postgres_connections, actor=actor, run_id=actor["session_id"])
    )
    with pytest.raises(GithubMarkdownSourceError, match="replay could not be recovered"):
        authority.import_markdown(
            actor_context=actor,
            operation_id=operation_id,
            run_id=actor["session_id"],
            source=source,
            policy_decision=policy,
        )
    assert _counts(postgres_connections) == before


def test_concurrent_identical_imports_commit_one_revision_and_one_evidence_event(
    postgres_connections,
):
    actor = _live_actor(postgres_connections)
    authority = _authority(postgres_connections)
    source = _source()
    operation_id = "018f0000-0000-7000-8000-00000000c045"
    policy = _policy(
        actor,
        operation_id=operation_id,
        operation_digest=source.operation_digest(operation_id),
        decision_id="018f0000-0000-7000-8000-00000000c046",
    )
    barrier = Barrier(2)

    def import_once():
        barrier.wait(timeout=5)
        return authority.import_markdown(
            actor_context=actor,
            operation_id=operation_id,
            run_id=actor["session_id"],
            source=source,
            policy_decision=policy,
        )

    with ThreadPoolExecutor(max_workers=2) as workers:
        results = tuple(workers.map(lambda _index: import_once(), range(2)))
    assert sorted(result.replayed for result in results) == [False, True]
    assert results[0].result == results[1].result
    assert _counts(postgres_connections) == (1, 1, 1)


def test_operation_id_is_single_use_across_sources_and_operation_kinds(postgres_connections):
    actor = _live_actor(postgres_connections)
    authority = _authority(postgres_connections)
    source = _source()
    operation_id = "018f0000-0000-7000-8000-00000000c047"
    authority.import_markdown(
        actor_context=actor,
        operation_id=operation_id,
        run_id=actor["session_id"],
        source=source,
        policy_decision=_policy(
            actor,
            operation_id=operation_id,
            operation_digest=source.operation_digest(operation_id),
            decision_id="018f0000-0000-7000-8000-00000000c048",
        ),
    )
    before = _counts(postgres_connections)
    assert _operation_count(postgres_connections) == 1

    other_source = replace(
        source,
        path="docs/other.md",
        content="# Other\n\nOne operation ID cannot authorize a second source.\n",
    )
    with pytest.raises(Exception, match="operation conflicts"):
        authority.import_markdown(
            actor_context=actor,
            operation_id=operation_id,
            run_id=actor["session_id"],
            source=other_source,
            policy_decision=_policy(
                actor,
                operation_id=operation_id,
                operation_digest=other_source.operation_digest(operation_id),
                decision_id="018f0000-0000-7000-8000-00000000c049",
            ),
        )
    with pytest.raises(Exception, match="operation conflicts"):
        authority.revoke_source(
            actor_context=actor,
            operation_id=operation_id,
            run_id=actor["session_id"],
            source_identity=source.source_identity,
            policy_decision=_policy(
                actor,
                operation_id=operation_id,
                operation_digest=sha256_digest(
                    {"operation_id": operation_id, "source_identity": source.source_identity}
                ),
                decision_id="018f0000-0000-7000-8000-00000000c050",
            ),
        )
    assert _counts(postgres_connections) == before
    assert _operation_count(postgres_connections) == 1


def test_direct_sql_rejects_poisoned_policy_and_future_evidence_without_writes(
    postgres_connections,
):
    actor = _live_actor(postgres_connections)
    authority = _authority(postgres_connections)
    source = _source()
    operation_id = "018f0000-0000-7000-8000-00000000c051"
    run_id = "018f0000-0000-7000-8000-00000000c052"
    policy = _policy(
        actor,
        operation_id=operation_id,
        operation_digest=source.operation_digest(operation_id),
        decision_id="018f0000-0000-7000-8000-00000000c053",
    )
    payload = _import_payload(
        actor=actor,
        operation_id=operation_id,
        run_id=run_id,
        source=source,
        policy=policy,
    )
    before = _counts(postgres_connections)
    assert _run_head_count(postgres_connections, actor=actor, run_id=run_id) == 0

    poisoned_policy = copy.deepcopy(policy)
    poisoned_policy["extensions"] = {"ignored": "must fail closed"}
    apply_object_digest(poisoned_policy)
    with postgres_connections["writer"]() as connection, connection.cursor() as cursor:
        forged_actor = copy.deepcopy(actor)
        forged_actor["actor_id"] = "018f0000-0000-7000-8000-00000000c054"
        with pytest.raises(Exception, match="outside actor scope"):
            cursor.execute(
                "SELECT gah_import_github_markdown(%s::jsonb,%s::jsonb,%s::jsonb)",
                (json.dumps(forged_actor), json.dumps({}), json.dumps({})),
            )
        connection.rollback()
        with pytest.raises(Exception, match="policy is not an exact bounded authorization"):
            cursor.execute(
                "SELECT gah_import_github_markdown(%s::jsonb,%s::jsonb,%s::jsonb)",
                (
                    json.dumps(actor),
                    json.dumps(
                        _import_payload(
                            actor=actor,
                            operation_id=operation_id,
                            run_id=run_id,
                            source=source,
                            policy=poisoned_policy,
                        )
                    ),
                    json.dumps({}),
                ),
            )
        connection.rollback()
        evidence_payload = {
            "actor_id": actor["actor_id"],
            "operation_id": operation_id,
            "operation_digest": payload["operation_digest"],
            "source": _evidence_source_metadata(source),
            "policy_decision_digest": policy["decision_digest"],
        }
        evidence = authority._store._prepare_evidence(
            cursor=cursor,
            actor=actor,
            run_id=run_id,
            event_kind="knowledge.github_markdown_imported",
            policy_ref={
                "record_type": "policy_decision",
                "record_id": policy["decision_id"],
                "record_digest": policy["decision_digest"],
            },
            payload=evidence_payload,
        )
        poisoned_evidence = copy.deepcopy(evidence)
        future = "2099-01-01T00:00:00.000Z"
        poisoned_evidence["recorded_at"] = future
        poisoned_evidence["draft"]["occurred_at"] = future
        poisoned_evidence["draft_digest"] = sha256_digest(poisoned_evidence["draft"])
        apply_object_digest(poisoned_evidence)
        with pytest.raises(Exception, match="evidence is invalid"):
            cursor.execute(
                "SELECT gah_import_github_markdown(%s::jsonb,%s::jsonb,%s::jsonb)",
                (json.dumps(actor), json.dumps(payload), json.dumps(poisoned_evidence)),
            )
        connection.rollback()
        chronologically_poisoned = authority._store._prepare_evidence(
            cursor=cursor,
            actor=actor,
            run_id=run_id,
            event_kind="knowledge.github_markdown_imported",
            policy_ref={
                "record_type": "policy_decision",
                "record_id": policy["decision_id"],
                "record_digest": policy["decision_digest"],
            },
            payload=evidence_payload,
        )
        before_authorization = _timestamp(datetime.now(timezone.utc) - timedelta(seconds=2))
        chronologically_poisoned["recorded_at"] = before_authorization
        chronologically_poisoned["draft"]["occurred_at"] = before_authorization
        chronologically_poisoned["draft_digest"] = sha256_digest(chronologically_poisoned["draft"])
        apply_object_digest(chronologically_poisoned)
        with pytest.raises(Exception, match="evidence is invalid"):
            cursor.execute(
                "SELECT gah_import_github_markdown(%s::jsonb,%s::jsonb,%s::jsonb)",
                (json.dumps(actor), json.dumps(payload), json.dumps(chronologically_poisoned)),
            )
        connection.rollback()
    assert _counts(postgres_connections) == before
    assert _run_head_count(postgres_connections, actor=actor, run_id=run_id) == 0


def test_secret_like_content_and_direct_sql_runtime_bypass_fail_without_mutation(
    postgres_connections,
):
    actor = _live_actor(postgres_connections)
    with pytest.raises(GithubMarkdownSourceError, match="credential material"):
        _source(content="token ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCDEF\n").validate()

    source = _source()
    operation_id = "018f0000-0000-7000-8000-00000000c021"
    policy = _policy(
        actor,
        operation_id=operation_id,
        operation_digest=source.operation_digest(operation_id),
        decision_id="018f0000-0000-7000-8000-00000000c022",
    )
    imported = _authority(postgres_connections).import_markdown(
        actor_context=actor,
        operation_id=operation_id,
        run_id=actor["session_id"],
        source=source,
        policy_decision=policy,
    )
    before = _counts(postgres_connections)

    for poison_number, content in enumerate(
        (
            "credential " + "sk" + "_live_" + "abcdefghijklmnopqrstuvwxyz0123456789\n",
            '{"password":"supersecret"}\n',
            'password = "supersecret"\n',
            'authorization = "Bearer abcdefghijklmnop"\n',
        ),
        start=0x24,
    ):
        poisoned_source = source.to_dict()
        poisoned_source["content"] = content
        poisoned_source["content_digest"] = sha256_digest(
            {"content": poisoned_source["content"], "media_type": "text/markdown"}
        )
        poisoned_operation = f"018f0000-0000-7000-8000-{poison_number:012x}"
        poisoned_payload = {
            "operation_id": poisoned_operation,
            "operation_digest": sha256_digest(
                {"operation_id": poisoned_operation, "source": poisoned_source}
            ),
            "run_id": actor["session_id"],
            "source": poisoned_source,
            "policy_decision": _policy(
                actor,
                operation_id=poisoned_operation,
                operation_digest=sha256_digest(
                    {"operation_id": poisoned_operation, "source": poisoned_source}
                ),
                decision_id=f"018f0000-0000-7000-8000-{poison_number + 1:012x}",
            ),
        }
        with postgres_connections["writer"]() as connection, connection.cursor() as cursor:
            with pytest.raises(Exception, match="source is invalid"):
                cursor.execute(
                    "SELECT gah_import_github_markdown(%s::jsonb,%s::jsonb,%s::jsonb)",
                    (json.dumps(actor), json.dumps(poisoned_payload), json.dumps({})),
                )
            connection.rollback()

    forged = copy.deepcopy(actor)
    forged["actor_id"] = "018f0000-0000-7000-8000-00000000c023"
    with postgres_connections["app"]() as connection, connection.cursor() as cursor:
        with pytest.raises(Exception, match="outside actor scope"):
            cursor.execute(
                "SELECT gah_retrieve_github_markdown(%s::jsonb,%s,%s)",
                (json.dumps(forged), "Roadmap", 1),
            )
        connection.rollback()
        with pytest.raises(Exception):
            cursor.execute("SELECT content FROM gah_github_markdown_revisions")
        connection.rollback()
        with pytest.raises(Exception):
            cursor.execute(
                "SELECT gah_import_github_markdown(%s::jsonb,%s::jsonb,%s::jsonb)",
                (json.dumps(actor), json.dumps({}), json.dumps({})),
            )
    assert _counts(postgres_connections) == before
    assert imported.result.content_digest == source.content_digest
