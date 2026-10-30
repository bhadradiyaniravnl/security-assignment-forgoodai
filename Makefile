.PHONY: help up down images apply secrets hooks status sentinel-policy security-test test dist \
        smoke e2e lifecycle containment specs github sentinel sentinel-completeness sentinel-policy-test

help:      ## List targets
	@grep -E '^[a-z0-9-]+:.*##' Makefile | sed 's/:.*## /	/' | expand -t 24

# ---- environment -------------------------------------------------------------------------------
up:        ## Colima VM, kind cluster, Cilium, gVisor, images, manifests, sentinel policy
	deploy/up.sh

down:      ## Export evidence and delete the cluster (STOP_VM=1 also stops Colima)
	deploy/down.sh

images:    ## Rebuild and load images into kind
	deploy/images.sh

apply:     ## Re-apply Kubernetes manifests
	kubectl apply -k deploy/k8s

secrets:   ## Load secrets/.env into the credproxy Secret
	deploy/secrets.sh

hooks:     ## Enable the repo's git hooks (pre-commit secret guard)
	git config core.hooksPath .githooks

status:    ## Platform pods and where they run
	kubectl get pods -A -o wide | grep -E 'sbx-|lab-ext|NAMESPACE'

dist:      ## Zip the last commit for review (git archive: never includes secrets/ or out/)
	@mkdir -p out && git archive --format=zip --prefix=sandboxed-agents/ -o out/sandboxed-agents.zip HEAD && echo out/sandboxed-agents.zip

sentinel-policy: ## Validate, diff and deploy the sentinel detection policy (FILE=...; CHECK_ONLY=1)
	deploy/sentinel-policy.sh $(FILE)

# ---- the assignment's one-command harness ------------------------------------------------------
security-test: ## Phase B (enforcement), A (agent under injection), C (utility) -> out/report.md
	python3 tests/security_test.py $(ARGS)

# ---- feature suites (tests/suites/) ------------------------------------------------------------
test: smoke e2e lifecycle containment specs sentinel sentinel-completeness sentinel-policy-test ## Every suite except github (needs the optional GitHub App)

smoke:     ## Boundary: gVisor, Cilium policies, lab ingress, quarantine
	tests/suites/smoke.sh

e2e:       ## Gateways, credproxy and evidence, with a real Claude Code call
	tests/suites/e2e.sh

lifecycle: ## sbxctl lifecycle, trigger-time rejections, reconciler, idle reaping
	tests/suites/lifecycle.sh

containment: ## Detection -> auto-containment -> two-source verification, fleet freeze
	tests/suites/containment.sh

specs:     ## Spec governance: baseline, authors, immutability, two-person approval, admission
	tests/suites/specs.sh

github:    ## Scoped GitHub App tokens, clone via credproxy, PR refusals (AGENT=1 opens a real PR)
	tests/suites/github.sh

sentinel:  ## Sentinel: isolation, verified shipping, containment with the control plane down, S2, S6
	tests/suites/sentinel.sh

sentinel-completeness: ## Sentinel S1: datapath request counts vs gateway evidence (fault-injected gateway)
	tests/suites/sentinel_completeness.sh

sentinel-policy-test: ## Detection policy: deploy, floor, custom rules, contain vs record, monitor mode
	tests/suites/sentinel_policy.sh
