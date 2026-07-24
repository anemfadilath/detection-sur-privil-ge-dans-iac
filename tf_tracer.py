#!/usr/bin/env python3
import os
import re
import glob


def _resolve_interpolations(value, tfvars):
    def repl(m):
        var = m.group(1)
        return tfvars.get(var, m.group(0))
    value = re.sub(r"\$\{var\.([a-zA-Z0-9_]+)\}", repl, value)
    return value


def build_terraform_index(tf_dir, tfvars=None):
    if tfvars is None:
        tfvars = {}

    index = []
    tf_files = glob.glob(os.path.join(tf_dir, "*.tf"))

    for path in tf_files:
        fname = os.path.basename(path)
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()

        i = 0
        while i < len(lines):
            line = lines[i]
            m = re.match(r'\s*resource\s+"(aws_iam_role_policy|aws_iam_role_policy_attachment)"\s+"([^"]+)"', line)
            if m:
                res_type = m.group(1)
                res_name = m.group(2)
                decl_line = i + 1  
                address = f"{res_type}.{res_name}"

                body = []
                depth = line.count("{") - line.count("}")
                j = i + 1
                while j < len(lines) and depth > 0:
                    body.append(lines[j])
                    depth += lines[j].count("{") - lines[j].count("}")
                    j += 1
                body_text = "".join(body)

                policy_name = None
                policy_arn = None
                role_ref = None

                pn = re.search(r'name\s*=\s*"([^"]+)"', body_text)
                if pn:
                    policy_name = _resolve_interpolations(pn.group(1), tfvars)

                pa = re.search(r'policy_arn\s*=\s*"([^"]+)"', body_text)
                if pa:
                    policy_arn = pa.group(1)

                rr = re.search(r'role\s*=\s*aws_iam_role\.([a-zA-Z0-9_]+)', body_text)
                if rr:
                    role_ref = rr.group(1)

                index.append({
                    "address": address,
                    "file": fname,
                    "line": decl_line,
                    "resource_type": res_type,
                    "resource_name": res_name,
                    "policy_name": policy_name,
                    "policy_arn": policy_arn,
                    "role_ref": role_ref,
                })
                i = j
                continue
            i += 1

    return index


def trace(origin, source, tf_index):
   
    for entry in tf_index:
        if origin == "inline" and entry["policy_name"] == source:
            return f"{entry['address']} ({entry['file']}:{entry['line']})"
        if origin == "managed" and entry["policy_arn"] == source:
            return f"{entry['address']} ({entry['file']}:{entry['line']})"
    return f"[non localisé dans le .tf] {origin}:{source}"
          