.PHONY: up down images apply secrets status smoke e2e lifecycle containment specs github sentinel sentinel-s1 sentinel-policy sentinel-policy-test security-test hooks

up:        ## Colima VM, kind cluster, Cilium, gVisor, images, manifests
	deploy/up.sh

down:      ## Export evidence and delete the cluster (STOP_VM=1 also stops Colima)
	deploy/down.sh

images:    ## Rebuild and load images into kind
	deploy/images.sh

apply:     ## Re-apply Kubernetes manifests
	kubectl apply -k deploy/k8s

secrets:   ## Load secrets/.env into the credproxy Secret
	deploy/secrets.sh

status:
	kubectl get pods -A -o wide | grep -E 'sbx-|lab-ext|NAMESPACE'

smoke:     ## M1 boundary smoke test (gVisor, Cilium policies, lab ingress, containment)
	harness/m1_smoke.sh

e2e:       ## M2 end-to-end test (gateways, credproxy, evidence)
	harness/m2_e2e.sh

lifecycle: ## M3 session lifecycle test via sbxctl
	harness/m3_lifecycle.sh

containment: ## M4 detection -> auto-containment -> two-source verification
	harness/m4_containment.sh

specs:     ## M6 spec governance: baseline, authors, immutability, widening approval, admission backstop
	harness/m6_specs.sh

github:    ## GitHub flow: scoped tokens, clone via credproxy, PR refusals (AGENT=1 also opens a real draft PR)
	harness/m8_github.sh

sentinel:  ## S-P1: independent detection & response plane (incl. containment with the control plane down)
	harness/m9_sentinel.sh

sentinel-policy: ## Validate, diff and deploy the sentinel detection policy (FILE=policies/sentinel/detection.yaml; CHECK_ONLY=1)
	deploy/sentinel-policy.sh $(FILE)

sentinel-policy-test: ## Detection policy: floor, hot reload, monitor mode, custom match rules, response actions
	harness/m11_sentinel_policy.sh

sentinel-s1: ## S-P2: independent L7/L4 counts vs gateway evidence (S1), via lab fault injection
	harness/m10_sentinel_s1.sh

security-test: ## One command: phase B (enforcement), A (agent under injection), C (utility) -> out/report.md
	python3 harness/security_test.py $(ARGS)

hooks:     ## Enable the repo's git hooks (pre-commit secret guard)
	git config core.hooksPath scripts/git-hooks
