#!/usr/bin/env python3
"""RunPod pod management for the VulnFix-RL Phase 3 pilot.

Uses a locally installed runpod connector helper's authenticated
functions (point RUNPOD_CONNECTOR_BIN at its bin directory; no key
appears in this file, its arguments, or its output).

Commands:
  create   create the pilot pod (A100 80GB, PyTorch image, SSH key)
  get      pod state incl. costPerHr and runtime
  ssh      print the ssh command for the pod
  stop     stop the pod (billing stops for GPU; disk may still bill)
  delete   delete the pod (full termination)

The pod name is vulnfix-phase3-pilot. Creation parameters are the
ones recorded in pilot/RUN_SHEET.md.
"""
import json
import os
import sys

sys.path.insert(0, os.environ.get("RUNPOD_CONNECTOR_BIN", ""))
from runpod_api import graphql, rest  # noqa: E402

NAME = "vulnfix-phase3-pilot"
IMAGE = "runpod/pytorch:2.4.0-py3.11-cuda12.4.1-devel-ubuntu22.04"
GPU_IDS = ["NVIDIA A100 80GB PCIe", "NVIDIA A100-SXM4-80GB"]


def find_pod():
    out = graphql("{ myself { pods { id name desiredStatus "
                  "costPerHr runtime { uptimeInSeconds } } } }")
    for p in (out.get("data") or {}).get("myself", {}).get("pods", []):
        if p["name"] == NAME:
            return p
    return None


def cmd_create():
    """Create via the GraphQL podFindAndDeployOnDemand mutation.

    The connector helper's REST path (rest.runpod.io/v2) is retired:
    on 2026-11-06 it 301-redirected to the docs site, and the bare
    urllib user agent was Cloudflare-blocked (error 1010) before
    that. The GraphQL mutation below is the path verified live in
    the Phase 3 pre-flight: it reached RunPod's supply/balance logic
    and returned structured GraphQL responses. GPU type and cloud
    can be overridden with RP_GPU / RP_CLOUD.
    """
    existing = find_pod()
    if existing:
        print(f"pod already exists: {existing['id']} "
              f"status={existing['desiredStatus']}")
        return
    pubkey = open(os.path.expanduser(
        "~/.ssh/id_ed25519.pub")).read().strip()
    mutation = """
    mutation Deploy($input: PodFindAndDeployOnDemandInput) {
      podFindAndDeployOnDemand(input: $input) {
        id imageName name desiredStatus costPerHr
      }
    }
    """
    variables = {"input": {
        "cloudType": os.environ.get("RP_CLOUD", "COMMUNITY"),
        "gpuCount": 1,
        "volumeInGb": 0,
        "containerDiskInGb": 80,
        "gpuTypeId": os.environ.get("RP_GPU", GPU_IDS[0]),
        "name": NAME,
        "imageName": IMAGE,
        "dockerArgs": "",
        "ports": "22/tcp",
        "env": [{"key": "PUBLIC_KEY", "value": pubkey}],
    }}
    print(json.dumps(graphql(mutation, variables), indent=2))


def cmd_get():
    p = find_pod()
    print(json.dumps(p, indent=2) if p else "no pod found")


def cmd_ssh():
    """Print the pod's runtime/port record via GraphQL (the REST
    path is retired; see cmd_create). Untested against a live pod."""
    p = find_pod()
    if not p:
        print("no pod found")
        return
    q = ("{ myself { pods { id name runtime { ports { ip isIpPublic "
         "privatePort publicPort type } } } } }")
    out = graphql(q)
    for pod in (out.get("data") or {}).get("myself", {}).get("pods", []):
        if pod["id"] == p["id"]:
            print(json.dumps(pod, indent=2))
            return
    print("pod runtime not available yet")


def cmd_stop():
    """GraphQL podStop. Untested against a live pod (none existed
    during the Phase 3 pre-flight); the create mutation in this file
    is the verified path."""
    p = find_pod()
    if not p:
        print("no pod found")
        return
    q = ("mutation { podStop(input: {podId: \"%s\"}) "
         "{ id desiredStatus } }") % p["id"]
    print(json.dumps(graphql(q), indent=2))


def cmd_delete():
    """GraphQL podTerminate. Untested against a live pod (see
    cmd_stop); verify with `get` afterwards."""
    p = find_pod()
    if not p:
        print("no pod found")
        return
    q = ("mutation { podTerminate(input: {podId: \"%s\"}) "
         "{ id desiredStatus } }") % p["id"]
    print(json.dumps(graphql(q), indent=2))


if __name__ == "__main__":
    cmds = {"create": cmd_create, "get": cmd_get, "ssh": cmd_ssh,
            "stop": cmd_stop, "delete": cmd_delete}
    if len(sys.argv) < 2 or sys.argv[1] not in cmds:
        print(__doc__)
        sys.exit(2)
    cmds[sys.argv[1]]()
