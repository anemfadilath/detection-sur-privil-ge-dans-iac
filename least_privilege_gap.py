#!/usr/bin/env python3
import argparse
import os
import sys
import time

import boto3

import tf_tracer  
import html_report  

try:
    from policyuniverse.expander_minimizer import expand_policy
    HAS_POLICYUNIVERSE = True
except ImportError:
    HAS_POLICYUNIVERSE = False


def get_granted_permissions(iam, role_name):
    """Liste les permissions accordées avec leur mécanisme d'octroi."""
    granted = []

    for pname in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
        doc = iam.get_role_policy(RoleName=role_name, PolicyName=pname)["PolicyDocument"]
        for action in _extract_actions(doc):
            granted.append({"action": action, "origin": "inline", "source": pname})

    for pol in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]:
        arn = pol["PolicyArn"]
        vid = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
        doc = iam.get_policy_version(PolicyArn=arn, VersionId=vid)["PolicyVersion"]["Document"]
        for action in _extract_actions(doc):
            granted.append({"action": action, "origin": "managed", "source": arn})

    return granted


def _extract_actions(policy_doc):
    actions = []
    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        act = stmt.get("Action", [])
        if isinstance(act, str):
            act = [act]
        actions.extend(act)
    return actions


def expand_action(action, observed_actions):
    if "*" not in action:
        return [action], True

    if HAS_POLICYUNIVERSE:
        fake_policy = {"Statement": [{"Effect": "Allow", "Action": [action], "Resource": "*"}]}
        expanded = expand_policy(policy=fake_policy)["Statement"][0]["Action"]
        return [a for a in expanded], True

    service = action.split(":")[0]
    matched = [a for a in observed_actions if a.startswith(service + ":")]
    return matched if matched else [action], False


def get_used_actions(athena, db, table, output, roles):
    like = " OR ".join(
        [f"useridentity.sessioncontext.sessionissuer.username = '{r}'" for r in roles]
    )
    query = f"""
        SELECT useridentity.sessioncontext.sessionissuer.username AS role_name,
               eventsource, eventname
        FROM {db}.{table}
        WHERE ({like})
        GROUP BY 1, 2, 3
    """
    exec_id = athena.start_query_execution(
        QueryString=query,
        ResultConfiguration={"OutputLocation": output},
    )["QueryExecutionId"]
    print(f"  Requête Athena lancée (id={exec_id[:8]}...), attente...")
    _wait_for_athena(athena, exec_id)

    used = {r: set() for r in roles}
    paginator = athena.get_paginator("get_query_results")
    first = True
    for page in paginator.paginate(QueryExecutionId=exec_id):
        for row in page["ResultSet"]["Rows"]:
            if first:
                first = False
                continue
            cols = [c.get("VarCharValue", "") for c in row["Data"]]
            if len(cols) < 3:
                continue
            role_name = cols[0]
            action = _cloudtrail_to_iam_action(cols[1], cols[2])
            if role_name in used:
                used[role_name].add(action)
    return used


def _wait_for_athena(athena, exec_id, timeout=120):
    start = time.time()
    while True:
        st = athena.get_query_execution(QueryExecutionId=exec_id)["QueryExecution"]["Status"]["State"]
        if st in ("SUCCEEDED", "FAILED", "CANCELLED"):
            if st != "SUCCEEDED":
                reason = athena.get_query_execution(QueryExecutionId=exec_id)[
                    "QueryExecution"]["Status"].get("StateChangeReason", "")
                sys.exit(f"Requête Athena {st}: {reason}")
            return
        if time.time() - start > timeout:
            sys.exit("Timeout Athena (>120s).")
        time.sleep(2)


def _cloudtrail_to_iam_action(eventsource, eventname):
    return f"{eventsource.split('.')[0]}:{eventname}".lower()


def main():
    p = argparse.ArgumentParser(description="Least privilege gap + traçabilité Terraform")
    p.add_argument("--roles", nargs="+", required=True)
    p.add_argument("--athena-db", required=True)
    p.add_argument("--athena-table", required=True)
    p.add_argument("--athena-output", required=True)
    p.add_argument("--region", required=True)
    p.add_argument("--tf-dir", required=True,
                   help="Dossier contenant les fichiers .tf (pour la traçabilité).")
    p.add_argument("--name-prefix", default="lpg",
                   help="Valeur de var.name_prefix pour résoudre les noms dans le .tf.")
    args = p.parse_args()

    session = boto3.Session(region_name=args.region)
    iam = session.client("iam")
    athena = session.client("athena")

    granted = {r: get_granted_permissions(iam, r) for r in args.roles}
    used = get_used_actions(athena, args.athena_db, args.athena_table,
                            args.athena_output, args.roles)

    tf_index = tf_tracer.build_terraform_index(
        args.tf_dir, tfvars={"name_prefix": args.name_prefix})

    report = {}
    for r in args.roles:
        used_set = used[r]

        granted_concrete = {}  
        exhaustive = True
        for entry in granted[r]:
            expanded, is_exh = expand_action(entry["action"], used_set)
            if not is_exh:
                exhaustive = False
            for a in expanded:
                a_norm = a.lower()
                if a_norm not in granted_concrete:
                    via_wc = "*" in entry["action"]
                    granted_concrete[a_norm] = (entry["origin"], entry["source"],
                                                via_wc, entry["action"])

        total = len(granted_concrete)
        gap = {a: meta for a, meta in granted_concrete.items() if a not in used_set}
        gap_count = len(gap)
        gap_ratio = gap_count / total if total else 0

        by_source = {}
        for a, (origin, source, via_wc, orig_action) in gap.items():
            key = tf_tracer.trace(origin, source, tf_index)
            by_source.setdefault(key, {"count": 0, "actions": []})
            by_source[key]["count"] += 1
            by_source[key]["actions"].append({
                "action": a,
                "via_wildcard": bool(via_wc),
                "wildcard": orig_action if via_wc else None,
            })

        report[r] = {
            "granted_actions": total,
            "used_actions": len(used_set),
            "gap_actions": gap_count,
            "gap_ratio_pct": round(gap_ratio * 100),
            "exhaustive": exhaustive,
            "gap_by_source": {
                k: {"count": v["count"],
                    "actions": sorted(v["actions"], key=lambda x: x["action"])}
                for k, v in by_source.items()},
            "used_list": sorted(used_set),
        }

    html_content = html_report.generate(report, args.roles, meta={"region": args.region})
    with open("gap_report.html", "w", encoding="utf-8") as f:
        f.write(html_content)

    html_path = os.path.abspath("gap_report.html")
    print(f"\nRapport HTML : file:///{html_path.replace(os.sep, '/')}")


if __name__ == "__main__":
    main()