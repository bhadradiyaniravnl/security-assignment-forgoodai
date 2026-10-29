.PHONY: up down images apply secrets status smoke e2e lifecycle hooks

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

hooks:     ## Enable the repo's git hooks (pre-commit secret guard)
	git config core.hooksPath scripts/git-hooks
