PYTHON ?= python3
TERRAFORM ?= terraform

.PHONY: validate validate-sno-trial test observe-sno-trial-readiness verify-sno-trial-readiness verify-platform-contract-source verify-dependency-sources verify-risk-collection verify-prerequisite-observation verify-operator-control-plane-readiness verify-lab-service-publication verify-lab-service-publication-replay terraform-fmt terraform-validate

validate:
	$(PYTHON) scripts/validate_repository.py
	$(PYTHON) scripts/validate_sno_trial_profile.py
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
	$(PYTHON) scripts/validate_foundation_observation.py
	$(PYTHON) scripts/operator_control_plane_readiness.py validate-policy
	$(PYTHON) scripts/lab_service_publication.py validate-policy
	$(PYTHON) scripts/lab_service_publication_replay.py validate-policy
	kubectl kustomize gitops/clusters/reference-lab | $(PYTHON) scripts/validate_rendered_gitops.py
	kubectl kustomize gitops/dependencies/reference-lab | $(PYTHON) scripts/validate_dependency_gitops.py
	kubectl kustomize gitops/products/reference-lab | $(PYTHON) scripts/validate_product_gitops.py

validate-sno-trial:
	$(PYTHON) scripts/validate_sno_trial_profile.py

observe-sno-trial-readiness:
	test -n "$(PROJECT_ID)"
	test -n "$(QUOTA_REQUEST_STATUS)"
	test -n "$(ASSESSMENT_ID)"
	test -n "$(OUTPUT)"
	$(PYTHON) scripts/sno_trial_readiness.py collect \
		--project-id "$(PROJECT_ID)" \
		--quota-request-status "$(QUOTA_REQUEST_STATUS)" \
		--assessment-id "$(ASSESSMENT_ID)" \
		--output "$(OUTPUT)"

verify-sno-trial-readiness:
	test -n "$(REPORT)"
	$(PYTHON) scripts/sno_trial_readiness.py verify --report "$(REPORT)"

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

verify-operator-control-plane-readiness:
	test -n "$(REPORT)"
	test -n "$(ASSESSED_AT)"
	$(PYTHON) scripts/operator_control_plane_readiness.py verify --report "$(REPORT)" --at "$(ASSESSED_AT)"

verify-lab-service-publication:
	test -n "$(REPORT)"
	$(PYTHON) scripts/lab_service_publication.py verify --report "$(REPORT)"

verify-lab-service-publication-replay:
	test -n "$(REPORT)"
	$(PYTHON) scripts/lab_service_publication_replay.py verify --report "$(REPORT)"

terraform-fmt:
	$(TERRAFORM) fmt -check -recursive infra/terraform

terraform-validate:
	$(TERRAFORM) -chdir=infra/terraform/bootstrap init -backend=false -input=false
	$(TERRAFORM) -chdir=infra/terraform/bootstrap validate
	$(TERRAFORM) -chdir=infra/terraform/foundation init -backend=false -input=false
	$(TERRAFORM) -chdir=infra/terraform/foundation validate
	$(TERRAFORM) -chdir=infra/terraform/sno-trial init -backend=false -input=false
	$(TERRAFORM) -chdir=infra/terraform/sno-trial validate
	$(TERRAFORM) -chdir=infra/terraform/sno-trial test
