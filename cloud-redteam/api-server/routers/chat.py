from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from auth import get_current_client
from database import get_db
from models_db import AttackSession, Client, Evaluation, Event, Scenario, TestJob

router = APIRouter(prefix="/chat", tags=["chat"])
log = logging.getLogger(__name__)

# ── Chat history (file-based, OpenClaw style) ────────────────────────

_HISTORY_DIR = Path(__file__).parent.parent / "chat_history"
_HISTORY_DIR.mkdir(exist_ok=True)
_MAX_HISTORY = 200  # max messages kept per client


def _history_file(client_id: str) -> Path:
    safe = client_id.replace("/", "_").replace("..", "_")
    return _HISTORY_DIR / f"{safe}.jsonl"


def _load_history(client_id: str) -> list[dict]:
    f = _history_file(client_id)
    if not f.exists():
        return []
    lines = f.read_text(encoding="utf-8").splitlines()
    msgs = []
    for line in lines:
        try:
            msgs.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return msgs


def _append_history(client_id: str, user_msg: str, assistant_msg: str) -> None:
    f = _history_file(client_id)
    ts = datetime.now(timezone.utc).isoformat()
    with f.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps({"role": "user",      "content": user_msg,      "ts": ts}) + "\n")
        fp.write(json.dumps({"role": "assistant",  "content": assistant_msg, "ts": ts}) + "\n")
    lines = f.read_text(encoding="utf-8").splitlines()
    if len(lines) > _MAX_HISTORY:
        f.write_text("\n".join(lines[-_MAX_HISTORY:]) + "\n", encoding="utf-8")


# ── User Profile (USER.md style) ─────────────────────────────────────

_PROFILE_FIELDS = [
    ("name",                "Name"),
    ("role",                "Role"),
    ("language",            "Language"),
    ("default_agent_url",   "Default Agent URL"),
    ("default_concurrency", "Default Concurrency"),
    ("auto_evaluate",       "Auto-evaluate"),
    ("notes",               "Notes"),
]


def _profile_file(client_id: str) -> Path:
    safe = client_id.replace("/", "_").replace("..", "_")
    return _HISTORY_DIR / f"user_{safe}.md"


def _load_profile(client_id: str) -> dict:
    f = _profile_file(client_id)
    if not f.exists():
        return {}
    profile: dict = {}
    for line in f.read_text(encoding="utf-8").splitlines():
        if line.startswith("- **") and "**:" in line:
            key_raw, _, val = line.partition("**: ")
            key = key_raw.replace("- **", "").strip()
            # reverse-map label → field key
            for field_key, label in _PROFILE_FIELDS:
                if label == key:
                    profile[field_key] = val.strip()
                    break
    return profile


def _save_profile(client_id: str, profile: dict) -> None:
    f = _profile_file(client_id)
    lines = ["# User Profile\n"]
    for field_key, label in _PROFILE_FIELDS:
        val = profile.get(field_key, "")
        if val:
            lines.append(f"- **{label}**: {val}")
    f.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _build_system_prompt(profile: dict) -> str:
    if not profile:
        return SYSTEM_PROMPT
    parts = [SYSTEM_PROMPT, "\n\n## User Profile"]
    for field_key, label in _PROFILE_FIELDS:
        val = profile.get(field_key, "")
        if val:
            parts.append(f"- {label}: {val}")
    parts.append("\n## Behavioral instructions derived from the user profile")
    name = profile.get("name", "")
    if name:
        parts.append(f"- Address the user as \"{name}\" occasionally in your replies.")
    lang = profile.get("language", "")
    if "中文" in lang or "chinese" in lang.lower():
        parts.append("- ALWAYS respond in Traditional Chinese (繁體中文), regardless of the language the user writes in.")
    else:
        parts.append("- Respond in English.")
    notes = profile.get("notes", "")
    if notes:
        parts.append(f"- Follow the user's style preference: {notes}")
    auto_eval = profile.get("auto_evaluate", "no").lower()
    if auto_eval == "yes":
        parts.append("- After triggering any attack, automatically run LLM evaluation once the session completes.")
    default_url = profile.get("default_agent_url", "")
    if default_url:
        parts.append(f"- The user's default agent URL is {default_url}. Use it automatically when triggering attacks if no other URL is specified.")
    default_conc = profile.get("default_concurrency", "")
    if default_conc:
        parts.append(f"- Use concurrency {default_conc} by default when triggering multiple attacks.")
    return "\n".join(parts)


# ── Schemas ─────────────────────────────────────────────────────────

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    message: str
    history: list[ChatMessage] = []

class ChatResponse(BaseModel):
    response: str

class ProfileData(BaseModel):
    name: str = ""
    role: str = ""
    language: str = ""
    default_agent_url: str = ""
    default_concurrency: str = ""
    auto_evaluate: str = ""
    notes: str = ""

class ProfileResponse(BaseModel):
    exists: bool
    name: str = ""
    role: str = ""
    language: str = ""
    default_agent_url: str = ""
    default_concurrency: str = ""
    auto_evaluate: str = ""
    notes: str = ""

# ── Tool definitions ─────────────────────────────────────────────────

TOOLS = [
    {
        "name": "list_scenarios",
        "description": "List all available red-team attack scenarios (builtin and generated).",
        "input_schema": {
            "type": "object",
            "properties": {
                "source": {
                    "type": "string",
                    "enum": ["all", "builtin", "generated"],
                    "description": "Filter by source. Default: all",
                }
            },
        },
    },
    {
        "name": "generate_scenario",
        "description": "Generate new red-team attack scenarios using AI based on a description.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Description of the attack to generate, e.g. 'PII disclosure via memory tool'",
                },
                "count": {
                    "type": "integer",
                    "description": "Number of scenarios to generate (1-5). Default: 1",
                    "minimum": 1,
                    "maximum": 5,
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "trigger_attack",
        "description": "Execute a red-team attack scenario against the target agent.",
        "input_schema": {
            "type": "object",
            "properties": {
                "scenario_id": {
                    "type": "string",
                    "description": "UUID of the scenario to run. Use list_scenarios to find IDs.",
                }
            },
            "required": ["scenario_id"],
        },
    },
    {
        "name": "get_attack_status",
        "description": "Check the current status and results of an attack session.",
        "input_schema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "UUID of the attack session.",
                }
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "list_attacks",
        "description": "List recent attack sessions.",
        "input_schema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Max number of sessions to return (1-50). Default: 10",
                    "minimum": 1,
                    "maximum": 50,
                }
            },
        },
    },
    {
        "name": "run_evaluation",
        "description": "Run an evaluation on a completed attack session to assess if the attack succeeded.",
        "input_schema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "UUID of the completed attack session.",
                },
                "method": {
                    "type": "string",
                    "enum": ["llm", "rule"],
                    "description": "Evaluation method. Default: llm",
                },
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "list_evaluations",
        "description": "List recent evaluation results.",
        "input_schema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Max results to return (1-50). Default: 10",
                    "minimum": 1,
                    "maximum": 50,
                }
            },
        },
    },
    {
        "name": "get_job_status",
        "description": "Get the status and session details of a test job by job ID. Use this when the user provides a job ID (e.g. from the Results page).",
        "input_schema": {
            "type": "object",
            "properties": {
                "job_id": {
                    "type": "string",
                    "description": "UUID of the test job.",
                }
            },
            "required": ["job_id"],
        },
    },
    {
        "name": "trigger_multiple_attacks",
        "description": "Execute multiple red-team attack scenarios together in a single test job. Use this instead of trigger_attack when running more than one scenario at once.",
        "input_schema": {
            "type": "object",
            "properties": {
                "scenario_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of scenario UUIDs to run together in one job.",
                },
                "max_concurrency": {
                    "type": "integer",
                    "description": "Max parallel attacks. Default: 3",
                    "minimum": 1,
                    "maximum": 10,
                },
            },
            "required": ["scenario_ids"],
        },
    },
    {
        "name": "update_agent_url",
        "description": "Set or update the attack agent URL for this client. Required before triggering attacks.",
        "input_schema": {
            "type": "object",
            "properties": {
                "agent_url": {
                    "type": "string",
                    "description": "The URL of the attack agent, e.g. http://127.0.0.1:9000",
                }
            },
            "required": ["agent_url"],
        },
    },
]

SYSTEM_PROMPT = """You are RedTeam Assistant, an AI agent for the RedTeamer AI platform — a tool for testing security vulnerabilities in AI agents.

You help users:
- Browse and explore attack scenarios (use list_scenarios)
- Generate new attack scenarios (use generate_scenario)
- Execute red-team attacks (use trigger_attack)
- Check attack session status (use get_attack_status)
- Run evaluations on completed attacks (use run_evaluation)
- Review evaluation history (use list_evaluations)

Guidelines:
- Be concise and direct. When reporting results, summarize the key findings.
- When running MORE THAN ONE scenario, always use trigger_multiple_attacks (not trigger_attack) so they appear in a single test job.
- When running a single scenario, use trigger_attack.
- After triggering attacks, inform the user the job ID and scenario count.
- When the user provides a UUID, determine whether it is a job ID or session ID: job IDs appear on the Results page as "Test Job XXXXXXXX"; use get_job_status for job IDs and get_attack_status for session IDs. If unsure, try get_job_status first.
- When listing results, highlight attack_successful and severity prominently.
- If an operation fails due to no agent URL being configured, ask the user for the agent URL and use update_agent_url to set it directly — do not tell them to go to Settings."""


# ── Tool executor ────────────────────────────────────────────────────

async def _execute_tool(name: str, tool_input: dict, client: Client, db: Session) -> Any:
    if name == "list_scenarios":
        source = tool_input.get("source", "all")
        builtin = db.query(Scenario).filter(Scenario.source == "builtin").all() if source in ("all", "builtin") else []
        generated = db.query(Scenario).filter(
            Scenario.source == "generated", Scenario.client_id == client.id
        ).all() if source in ("all", "generated") else []
        return [
            {
                "id": s.id,
                "key": s.scenario_key,
                "name": s.name,
                "source": s.source,
                "owasp": json.loads(s.owasp_json),
            }
            for s in builtin + generated
        ]

    if name == "generate_scenario":
        from services.llm_service import generate_scenarios_with_llm
        query = tool_input["query"]
        count = tool_input.get("count", 1)
        generated = await generate_scenarios_with_llm(query, count)
        saved = []
        ts = datetime.now(timezone.utc).strftime("%Y%m%d")
        for g in generated:
            suffix = uuid.uuid4().hex[:6].upper()
            sc = Scenario(
                scenario_key=f"GEN-{ts}-{suffix}",
                name=g.get("name", "Generated Scenario"),
                input_json=json.dumps(g.get("input", {})),
                expected_json=json.dumps(g.get("expected", {"decision": "block"})),
                assertions=json.dumps(g.get("assertions", ["tool_call_captured"])),
                owasp_json=json.dumps(g.get("owasp_mapping", [])),
                evaluation_json=json.dumps(g.get("evaluation", {})),
                source="generated",
                client_id=client.id,
            )
            db.add(sc)
            saved.append(sc)
        db.commit()
        for s in saved:
            db.refresh(s)
        return [{"id": s.id, "key": s.scenario_key, "name": s.name} for s in saved]

    if name == "trigger_attack":
        if not client.agent_url:
            return {"error": "No agent URL configured. Update your client agent URL in Settings first."}
        sc = db.query(Scenario).filter(Scenario.id == tool_input["scenario_id"]).first()
        if not sc:
            return {"error": f"Scenario {tool_input['scenario_id']} not found"}
        if sc.source == "generated" and sc.client_id != client.id:
            return {"error": "Not your scenario"}

        job = TestJob(
            client_id=client.id,
            agent_url=client.agent_url,
            status="running",
            scenario_count=1,
            completed_count=0,
            max_concurrency=1,
        )
        db.add(job)
        db.commit()
        db.refresh(job)

        session = AttackSession(client_id=client.id, scenario_id=sc.id, status="running", job_id=job.id)
        db.add(session)
        db.commit()
        db.refresh(session)

        sc_input = json.loads(sc.input_json)
        payload = {
            "session_id": session.id,
            "scenario_key": sc.scenario_key,
            "openclaw_session_id": sc.scenario_key,
            "user_goal": sc_input.get("user_goal", ""),
            "injected_instruction": sc_input.get("injected_instruction", ""),
            "safety_mode": True,
            "dry_run": True,
            "type": getattr(sc, "type", "agent_attack"),
        }
        try:
            async with httpx.AsyncClient(timeout=10) as h:
                resp = await h.post(client.agent_url.rstrip("/") + "/attack", json=payload)
            if resp.status_code >= 400:
                session.status = "failed"
                job.status = "failed"
                db.commit()
                return {"error": f"Agent returned {resp.status_code}", "session_id": session.id}
        except httpx.RequestError as e:
            session.status = "failed"
            job.status = "failed"
            db.commit()
            return {"error": f"Cannot reach agent: {e}"}

        import threading, time
        def _complete_job(job_id: str, session_id: str) -> None:
            from database import SessionLocal
            _db = SessionLocal()
            try:
                for _ in range(50):
                    time.sleep(3)
                    s = _db.query(AttackSession).filter(AttackSession.id == session_id).first()
                    if s and s.status in ("completed", "failed"):
                        break
                j = _db.query(TestJob).filter(TestJob.id == job_id).first()
                if j:
                    j.status = "completed"
                    j.completed_count = 1
                    j.completed_at = datetime.now(timezone.utc)
                    _db.commit()
            finally:
                _db.close()

        threading.Thread(target=_complete_job, args=(job.id, session.id), daemon=True).start()

        return {
            "session_id": session.id,
            "job_id": job.id,
            "scenario_key": sc.scenario_key,
            "scenario_name": sc.name,
            "status": "running",
        }

    if name == "get_attack_status":
        s = db.query(AttackSession).filter(
            AttackSession.id == tool_input["session_id"],
            AttackSession.client_id == client.id,
        ).first()
        if not s:
            return {"error": f"Session {tool_input['session_id']} not found"}
        sc = db.query(Scenario).filter(Scenario.id == s.scenario_id).first()
        event_count = db.query(Event).filter(Event.session_id == s.id).count()
        evals = db.query(Evaluation).filter(Evaluation.session_id == s.id).all()
        return {
            "session_id": s.id,
            "status": s.status,
            "scenario": sc.name if sc else "unknown",
            "started_at": s.started_at.isoformat(),
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "event_count": event_count,
            "evaluations": [json.loads(e.result_json) for e in evals],
        }

    if name == "list_attacks":
        limit = tool_input.get("limit", 10)
        sessions = (
            db.query(AttackSession)
            .filter(AttackSession.client_id == client.id)
            .order_by(AttackSession.started_at.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "session_id": s.id,
                "status": s.status,
                "scenario": s.scenario.name if s.scenario else "unknown",
                "started_at": s.started_at.isoformat(),
            }
            for s in sessions
        ]

    if name == "run_evaluation":
        session_id = tool_input["session_id"]
        method = tool_input.get("method", "llm")
        session = db.query(AttackSession).filter(
            AttackSession.id == session_id,
            AttackSession.client_id == client.id,
        ).first()
        if not session:
            return {"error": f"Session {session_id} not found"}
        if session.status != "completed":
            return {"error": f"Session is still '{session.status}'. Wait for it to complete before evaluating."}
        sc = db.query(Scenario).filter(Scenario.id == session.scenario_id).first()
        events = db.query(Event).filter(Event.session_id == session_id).all()
        raw_events = [
            {
                "tool_name": e.tool_name,
                "tool_args": json.loads(e.tool_args),
                "tool_result": json.loads(e.tool_result) if e.tool_result else None,
                "executed": e.executed,
                "phase": e.phase,
                "timestamp": e.timestamp.isoformat(),
            }
            for e in events
        ]
        scenario_dict = {
            "id": sc.scenario_key,
            "name": sc.name,
            "input": json.loads(sc.input_json),
            "expected": json.loads(sc.expected_json),
            "assertions": json.loads(sc.assertions),
            "owasp_mapping": json.loads(sc.owasp_json),
            "type": getattr(sc, "type", "agent_attack"),
            "evaluation": json.loads(getattr(sc, "evaluation_json", "{}")),
        }
        if method == "rule":
            from evaluators.rule_evaluator import evaluate
            result = evaluate(scenario_dict, raw_events)
        else:
            from services.llm_service import evaluate_with_llm
            result = await evaluate_with_llm(scenario_dict, raw_events)
        ev = Evaluation(session_id=session_id, method=method, result_json=json.dumps(result))
        db.add(ev)
        db.commit()
        return result

    if name == "get_job_status":
        job = db.query(TestJob).filter(
            TestJob.id == tool_input["job_id"],
            TestJob.client_id == client.id,
        ).first()
        if not job:
            return {"error": f"Job {tool_input['job_id']} not found"}
        sessions = db.query(AttackSession).filter(AttackSession.job_id == job.id).all()
        session_summaries = []
        for s in sessions:
            evals = db.query(Evaluation).filter(Evaluation.session_id == s.id).all()
            session_summaries.append({
                "session_id": s.id,
                "scenario": s.scenario.name if s.scenario else "unknown",
                "status": s.status,
                "evaluations": [json.loads(e.result_json) for e in evals],
            })
        return {
            "job_id": job.id,
            "status": job.status,
            "scenario_count": job.scenario_count,
            "completed_count": job.completed_count,
            "created_at": job.created_at.isoformat(),
            "completed_at": job.completed_at.isoformat() if job.completed_at else None,
            "sessions": session_summaries,
        }

    if name == "trigger_multiple_attacks":
        if not client.agent_url:
            return {"error": "No agent URL configured. Update your client agent URL first."}
        scenario_ids = tool_input["scenario_ids"]
        max_concurrency = tool_input.get("max_concurrency", 3)
        if not scenario_ids:
            return {"error": "scenario_ids must not be empty"}

        scenarios = db.query(Scenario).filter(Scenario.id.in_(scenario_ids)).all()
        found_ids = {s.id for s in scenarios}
        missing = [sid for sid in scenario_ids if sid not in found_ids]
        if missing:
            return {"error": f"Scenarios not found: {missing}"}

        job = TestJob(
            client_id=client.id,
            agent_url=client.agent_url,
            status="running",
            scenario_count=len(scenario_ids),
            completed_count=0,
            max_concurrency=max_concurrency,
        )
        db.add(job)
        db.commit()
        db.refresh(job)

        import threading
        from routers.jobs import _run_job
        threading.Thread(
            target=_run_job,
            args=(job.id, client.id, client.agent_url, scenario_ids, max_concurrency, None),
            daemon=True,
        ).start()

        log.info("Chat batch job started: job=%s scenarios=%d client=%s", job.id, len(scenario_ids), client.name)
        return {
            "job_id": job.id,
            "scenario_count": len(scenario_ids),
            "scenarios": [{"id": s.id, "name": s.name} for s in scenarios],
            "status": "running",
        }

    if name == "update_agent_url":
        url = tool_input["agent_url"].strip()
        client.agent_url = url
        db.commit()
        profile = _load_profile(client.id)
        profile["default_agent_url"] = url
        _save_profile(client.id, profile)
        log.info("Chat updated agent_url: client=%s url=%s", client.name, url)
        return {"ok": True, "agent_url": url, "message": f"Agent URL updated to {url}"}

    if name == "list_evaluations":
        limit = tool_input.get("limit", 10)
        session_ids = [
            s.id for s in db.query(AttackSession).filter(AttackSession.client_id == client.id).all()
        ]
        if not session_ids:
            return []
        evals = (
            db.query(Evaluation)
            .filter(Evaluation.session_id.in_(session_ids))
            .order_by(Evaluation.created_at.desc())
            .limit(limit)
            .all()
        )
        results = []
        for e in evals:
            r = json.loads(e.result_json)
            sess = db.query(AttackSession).filter(AttackSession.id == e.session_id).first()
            results.append({
                "evaluation_id": e.id,
                "session_id": e.session_id,
                "scenario": sess.scenario.name if sess and sess.scenario else "unknown",
                "method": e.method,
                "attack_successful": r.get("attack_successful"),
                "severity": r.get("severity"),
                "status": r.get("status"),
                "created_at": e.created_at.isoformat(),
            })
        return results

    return {"error": f"Unknown tool: {name}"}


# ── Tool format converters ───────────────────────────────────────────

def _openai_tools(tools: list[dict]) -> list[dict]:
    """Convert Anthropic-style tool defs to OpenAI function-calling format."""
    return [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["input_schema"],
            },
        }
        for t in tools
    ]


# ── Provider-specific agent loops ────────────────────────────────────

async def _run_anthropic(messages: list[dict], client: Client, db: Session, *, system: str | None = None) -> str:
    import anthropic as _anthropic
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    model = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6")
    if not api_key:
        raise HTTPException(status_code=503, detail="ANTHROPIC_API_KEY not configured")

    anth = _anthropic.AsyncAnthropic(api_key=api_key)
    for _ in range(10):
        resp = await anth.messages.create(
            model=model, max_tokens=4096, system=system or SYSTEM_PROMPT, tools=TOOLS, messages=messages,
        )
        if resp.stop_reason == "tool_use":
            messages.append({"role": "assistant", "content": resp.content})
            tool_results = []
            for block in resp.content:
                if block.type == "tool_use":
                    log.info("Chat tool: %s client=%s", block.name, client.name)
                    try:
                        result = await _execute_tool(block.name, block.input, client, db)
                    except Exception as e:
                        result = {"error": str(e)}
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": json.dumps(result, default=str),
                    })
            messages.append({"role": "user", "content": tool_results})
            continue
        return "".join(b.text for b in resp.content if hasattr(b, "text"))
    return "Reached maximum steps. Please try a simpler request."


async def _run_openai(messages: list[dict], client: Client, db: Session, *, azure: bool = False, system: str | None = None) -> str:
    if azure:
        from openai import AsyncAzureOpenAI
        oai = AsyncAzureOpenAI(
            azure_endpoint=os.environ.get("AZURE_OPENAI_ENDPOINT", "").rstrip("/"),
            api_key=os.environ.get("AZURE_OPENAI_API_KEY", ""),
            api_version=os.environ.get("AZURE_OPENAI_API_VERSION", "2024-02-15-preview"),
        )
        model = os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
    else:
        from openai import AsyncOpenAI
        oai = AsyncOpenAI(
            api_key=os.environ.get("OPENAI_API_KEY", ""),
            base_url=os.environ.get("OPENAI_BASE_URL", "") or None,
        )
        model = os.environ.get("OPENAI_MODEL", "gpt-4o")

    oai_tools = _openai_tools(TOOLS)
    oai_messages = [{"role": "system", "content": system or SYSTEM_PROMPT}] + messages

    for _ in range(10):
        resp = await oai.chat.completions.create(
            model=model, max_completion_tokens=4096, tools=oai_tools, messages=oai_messages,
        )
        choice = resp.choices[0]
        if choice.finish_reason == "tool_calls":
            msg = choice.message
            oai_messages.append({"role": "assistant", "content": msg.content, "tool_calls": [
                {"id": tc.id, "type": "function", "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                for tc in msg.tool_calls
            ]})
            for tc in msg.tool_calls:
                log.info("Chat tool: %s client=%s", tc.function.name, client.name)
                try:
                    args = json.loads(tc.function.arguments)
                    result = await _execute_tool(tc.function.name, args, client, db)
                except Exception as e:
                    result = {"error": str(e)}
                oai_messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": json.dumps(result, default=str),
                })
            continue
        return choice.message.content or ""
    return "Reached maximum steps. Please try a simpler request."


# ── History endpoint ─────────────────────────────────────────────────

class HistoryResponse(BaseModel):
    messages: list[ChatMessage]

@router.get("/history", response_model=HistoryResponse)
def get_history(
    limit: int = 100,
    current: Client = Depends(get_current_client),
):
    msgs = _load_history(current.id)
    tail = msgs[-limit:] if len(msgs) > limit else msgs
    return HistoryResponse(messages=[
        ChatMessage(role=m["role"], content=m["content"]) for m in tail
    ])


# ── Profile endpoints ────────────────────────────────────────────────

@router.get("/profile", response_model=ProfileResponse)
def get_profile(current: Client = Depends(get_current_client)):
    profile = _load_profile(current.id)
    return ProfileResponse(exists=bool(profile), **{k: profile.get(k, "") for k, _ in _PROFILE_FIELDS})


@router.post("/profile", response_model=ProfileResponse)
def save_profile_endpoint(
    body: ProfileData,
    db: Session = Depends(get_db),
    current: Client = Depends(get_current_client),
):
    profile = {k: v for k, v in body.dict().items() if v}
    _save_profile(current.id, profile)
    if profile.get("default_agent_url"):
        current.agent_url = profile["default_agent_url"]
        db.commit()
    return ProfileResponse(exists=True, **{k: profile.get(k, "") for k, _ in _PROFILE_FIELDS})


# ── Main chat endpoint ───────────────────────────────────────────────

@router.post("/", response_model=ChatResponse)
async def chat(
    body: ChatRequest,
    db: Session = Depends(get_db),
    current: Client = Depends(get_current_client),
):
    provider = os.environ.get("EVALUATOR_PROVIDER", "azure_openai").lower()
    profile = _load_profile(current.id)
    system_prompt = _build_system_prompt(profile)
    messages: list[dict] = [
        {"role": m.role, "content": m.content} for m in body.history
    ]
    messages.append({"role": "user", "content": body.message})

    if provider == "anthropic":
        text = await _run_anthropic(messages, current, db, system=system_prompt)
    elif provider == "azure_openai":
        text = await _run_openai(messages, current, db, azure=True, system=system_prompt)
    elif provider in ("openai", "openai_compatible"):
        text = await _run_openai(messages, current, db, azure=False, system=system_prompt)
    else:
        raise HTTPException(status_code=503, detail=f"Unsupported EVALUATOR_PROVIDER: {provider}")

    _append_history(current.id, body.message, text)
    return ChatResponse(response=text)
