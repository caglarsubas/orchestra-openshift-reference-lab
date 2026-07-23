PYTHON ?= python3
TERRAFORM ?= terraform

.PHONY: validate test verify-platform-contract-source verify-dependency-sources verify-risk-collection verify-prerequisite-observation terraform-fmt terraform-validate

validate:
	$(PYTHON) scripts/validate_repository.py
	$(PYTHON) scripts/validate_release_set.py
	$(PYTHON) scripts/validate_reference_lab_contract_intake.py
	$(PYTHON) scripts/validate_dependency_bom.py
	$(PYTHON) scripts/validate_dependency_admission.py
	$(PYTHON) scripts/validate_dependency_supply_chain.py
	$(PYTHON) scripts/validate_dependency_risk_intake.py
	$(PYTHON) scripts/validate_dependency_risk_execution.py
	$(PYTHON) scripts/validate_dependency_risk_collection_execution.py
	$(PYTHON) scripts/validate_dependency_risk_custody_verification.py
	$(PYTHON) scripts/validate_dependency_gitops_candidate.py
	$(PYTHON) scripts/validate_prerequisite_policy.py
	$(PYTHON) scripts/validate_foundation_apply_execution.py
	kubectl kustomize gitops/clusters/reference-lab | $(PYTHON) scripts/validate_rendered_gitops.py
	kubectl kustomize gitops/dependencies/reference-lab | $(PYTHON) scripts/validate_dependency_gitops.py
	kubectl kustomize gitops/products/reference-lab | $(PYTHON) scripts/validate_product_gitops.py

test:
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v

verify-platform-contract-source:
	test -n "$(PLATFORM_REPOSITORY)"
	$(PYTHON) scripts/validate_reference_lab_contract_intake.py --platform-repository "$(PLATFORM_REPOSITORY)"

verify-dependency-sources:
	$(PYTHON) scripts/verify_dependency_sources.py
	$(PYTHON) scripts/verify_dependency_signatures.py

verify-risk-collection:
	test -n "$(MANIFEST)"
	$(PYTHON) scripts/verify_dependency_risk_collection.py --manifest "$(MANIFEST)"

verify-prerequisite-observation:
	test -n "$(OBSERVATION)"
	$(PYTHON) scripts/validate_prerequisite_observation.py --observation "$(OBSERVATION)"

terraform-fmt:
	$(TERRAFORM) fmt -check -recursive infra/terraform

terraform-validate:
	$(TERRAFORM) -chdir=infra/terraform/bootstrap init -backend=false -input=false
	$(TERRAFORM) -chdir=infra/terraform/bootstrap validate
	$(TERRAFORM) -chdir=infra/terraform/foundation init -backend=false -input=false
	$(TERRAFORM) -chdir=infra/terraform/foundation validate
