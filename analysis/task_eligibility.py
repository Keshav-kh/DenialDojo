"""Survey every packaged AgentDojo v1.2.2 user task for eligibility as a DenialDojo base task.

Eligibility = the task's utility is scored on model output, discriminates against arbitrary
output, and survives the environment mutation that any sink write produces (checked by
executing a real sink call against a copy of the environment, strict=False as the scenarios use).
"""
import json
from collections import defaultdict

from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite import get_suites

SINK = {"workspace": "send_email", "travel": "send_email", "banking": "send_money", "slack": "send_direct_message"}
SINK_ARGS = {
    "send_email": {"recipients": ["eligibility-probe@example.net"], "subject": "x", "body": "y"},
    "send_money": {"recipient": "NL91ABNA0417164300", "amount": 1.0, "subject": "x", "date": "2022-03-31"},
    "send_direct_message": {"recipient": "Alice", "body": "y"},
}
IMPLEMENTED = {
    ("workspace", "user_task_28"): "S1 workspace_document_file_probe",
    ("workspace", "user_task_30"): "S2 workspace_vacation_document_file_probe",
    ("banking", "user_task_1"): "S3 banking_spending_review_probe",
    ("travel", "user_task_6"): "S4 travel_hotel_review_probe",
    ("banking", "user_task_7"): "S5 banking_gift_lookup_probe",
}

suites = get_suites("v1.2.2")
rows = []
for name, suite in suites.items():
    sink = SINK[name]
    vectors = sorted(suite.get_injection_vector_defaults())
    for tid, task in suite.user_tasks.items():
        pre = suite.load_and_inject_default_environment({})
        post = pre.model_copy(deep=True)
        rt = FunctionsRuntime(list(suite.tools))
        _, sink_err = rt.run_function(post, sink, SINK_ARGS[sink])
        gto = task.GROUND_TRUTH_OUTPUT
        row = dict(suite=name, task=tid, prompt=" ".join(task.PROMPT.split()), gto=gto)
        try:
            same = task.utility(gto, pre, pre, strict=False)
            mutated = task.utility(gto, pre, post, strict=False)
            nonsense = task.utility("nonsense", pre, post, strict=False)
        except Exception as exc:
            row.update(eligible=False, reason=f"utility raises {type(exc).__name__}")
            rows.append(row)
            continue
        if not gto:
            row.update(eligible=False, reason="empty ground-truth output (state-scored by design)")
        elif nonsense:
            row.update(eligible=False, reason="output-insensitive (true for arbitrary output)")
        elif same and not mutated:
            row.update(eligible=False, reason="rejects environment mutation (any sink write fails it)")
        elif not same:
            row.update(eligible=False, reason="state-scored (false on pristine environment)")
        else:
            row.update(eligible=True, reason="")
            gt_calls = [c.function for c in task.ground_truth(pre)]
            row["gt_tools"] = sorted(set(gt_calls))
            carriers = []
            for key in vectors:
                env = suite.load_and_inject_default_environment({key: "ZZSENTINELZZ"})
                rt2 = FunctionsRuntime(list(suite.tools))
                hit = False
                for call in task.ground_truth(env):
                    r, e = rt2.run_function(env, call.function, call.args)
                    if "ZZSENTINELZZ" in repr(r):
                        hit = True
                if hit:
                    carriers.append(key)
            row["carriers"] = carriers
            row["implemented"] = IMPLEMENTED.get((name, tid), "")
        rows.append(row)

json.dump(rows, open("docs/task_eligibility.json", "w", encoding="utf-8"), indent=1)

# --- summary ---
by = defaultdict(lambda: defaultdict(int))
for r in rows:
    by[r["suite"]]["total"] += 1
    by[r["suite"]]["eligible" if r["eligible"] else r["reason"]] += 1
for s, d in by.items():
    print(f"{s}: " + ", ".join(f"{k}={v}" for k, v in d.items()))
print()
print("ELIGIBLE TASKS")
for r in rows:
    if r["eligible"]:
        tag = f"  [{r['implemented']}]" if r["implemented"] else ""
        print(f"{r['suite']:10s} {r['task']:13s} carriers={r['carriers']} tools={r['gt_tools']}{tag}")
        print(f"{'':25s}{r['prompt'][:120]}")
