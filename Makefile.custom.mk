CONTROLLER_GEN_VERSION ?= v0.20.0

.PHONY: generate
generate: ## Regenerate deepcopy code for the in-repo API types.
	go run sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION) object paths=./api/...
