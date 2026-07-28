PYTHON ?= python3
TERRAFORM ?= terraform

.PHONY: validate validate-sno-trial validate-sno-trial-toolchain validate-sno-trial-workload-candidate validate-sno-trial-dependency-runtime-contracts validate-sno-trial-dependency-artifacts validate-sno-trial-dependency-risk validate-sno-trial-dependency-risk-custody validate-sno-trial-dependency-manifests validate-sno-trial-dependency-integrity-policy validate-sno-trial-product-artifacts validate-sno-trial-product-admission validate-sno-trial-operator-inputs validate-sno-trial-resource-exposure test observe-sno-trial-readiness verify-sno-trial-readiness observe-sno-trial-network-hygiene verify-sno-trial-network-hygiene observe-sno-trial-dns-delegation verify-sno-trial-dns-delegation observe-sno-trial-operator-path verify-sno-trial-operator-path observe-sno-trial-cluster verify-sno-trial-cluster observe-sno-trial-resource-exposure verify-sno-trial-resource-exposure observe-sno-trial-operator-inputs verify-sno-trial-operator-inputs observe-sno-trial-product-dry-run verify-sno-trial-product-dry-run create-sno-trial-render-admission verify-sno-trial-render-admission materialize-sno-trial-install-config inspect-sno-trial-toolchain verify-sno-trial-toolchain replay-sno-trial-product-artifacts verify-sno-trial-product-artifacts plan-sno-trial-product-admission-environment apply-sno-trial-product-admission-environment verify-sno-trial-product-admission-environment verify-sno-trial-product-admission verify-platform-contract-source verify-dependency-sources verify-risk-collection verify-prerequisite-observation verify-operator-control-plane-readiness verify-lab-service-publication verify-lab-service-publication-replay terraform-fmt terraform-validate
.PHONY: observe-sno-trial-dependency-inputs verify-sno-trial-dependency-inputs materialize-sno-trial-dependency-manifests verify-sno-trial-dependency-materialization observe-sno-trial-dependency-integrity verify-sno-trial-dependency-integrity validate-sno-trial-dependency-dry-run-contract observe-sno-trial-dependency-dry-run verify-sno-trial-dependency-dry-run
.PHONY: plan-reference-lab-environment apply-reference-lab-environment verify-reference-lab-environment

validate:
	$(PYTHON) scripts/validate_repository.py
	$(PYTHON) scripts/validate_sno_trial_profile.py
	$(PYTHON) scripts/sno_trial_resource_exposure.py validate-rate-card
	$(PYTHON) scripts/openshift_toolchain_intake.py validate-lock
	$(PYTHON) scripts/validate_sno_trial_workload_candidate.py
	$(PYTHON) scripts/validate_sno_trial_dependency_runtime_contracts.py
	$(PYTHON) scripts/validate_sno_trial_dependency_artifacts.py
	$(PYTHON) scripts/sno_trial_dependency_risk.py validate-policy
	$(PYTHON) scripts/sno_trial_dependency_risk_custody.py validate-policy
	$(PYTHON) scripts/validate_sno_trial_dependency_manifests.py
	$(PYTHON) scripts/sno_trial_dependency_integrity.py validate-policy
	$(PYTHON) scripts/sno_trial_dependency_dry_run.py validate-contract
	$(PYTHON) scripts/sno_trial_product_artifacts.py validate-lock
	$(PYTHON) scripts/sno_trial_product_artifact_admission.py validate-policy
	$(PYTHON) scripts/sno_trial_operator_inputs.py validate-lock
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
	kubectl kustomize gitops/dependencies/candidates/sno-trial >/dev/null
	kubectl kustomize gitops/products/reference-lab | $(PYTHON) scripts/validate_product_gitops.py

validate-sno-trial:
	$(PYTHON) scripts/validate_sno_trial_profile.py

validate-sno-trial-toolchain:
	$(PYTHON) scripts/openshift_toolchain_intake.py validate-lock

validate-sno-trial-workload-candidate:
	$(PYTHON) scripts/validate_sno_trial_workload_candidate.py

validate-sno-trial-dependency-runtime-contracts:
	$(PYTHON) scripts/validate_sno_trial_dependency_runtime_contracts.py

validate-sno-trial-dependency-artifacts:
	$(PYTHON) scripts/validate_sno_trial_dependency_artifacts.py

validate-sno-trial-dependency-risk:
	$(PYTHON) scripts/sno_trial_dependency_risk.py validate-policy

validate-sno-trial-dependency-risk-custody:
	$(PYTHON) scripts/sno_trial_dependency_risk_custody.py validate-policy

validate-sno-trial-dependency-manifests:
	$(PYTHON) scripts/validate_sno_trial_dependency_manifests.py
	kubectl kustomize gitops/dependencies/candidates/sno-trial >/dev/null

validate-sno-trial-dependency-integrity-policy:
	$(PYTHON) scripts/sno_trial_dependency_integrity.py validate-policy

validate-sno-trial-product-artifacts:
	$(PYTHON) scripts/sno_trial_product_artifacts.py validate-lock

validate-sno-trial-product-admission:
	$(PYTHON) scripts/sno_trial_product_artifact_admission.py validate-policy

validate-sno-trial-operator-inputs:
	$(PYTHON) scripts/sno_trial_operator_inputs.py validate-lock

validate-sno-trial-resource-exposure:
	$(PYTHON) scripts/sno_trial_resource_exposure.py validate-rate-card

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

observe-sno-trial-network-hygiene:
	test -n "$(PROJECT_ID)"
	test -n "$(ASSESSMENT_ID)"
	test -n "$(OUTPUT)"
	$(PYTHON) scripts/sno_trial_network_hygiene.py collect \
		--project-id "$(PROJECT_ID)" \
		--assessment-id "$(ASSESSMENT_ID)" \
		--output "$(OUTPUT)"

verify-sno-trial-network-hygiene:
	test -n "$(REPORT)"
	$(PYTHON) scripts/sno_trial_network_hygiene.py verify --report "$(REPORT)"

observe-sno-trial-dns-delegation:
	test -n "$(PROJECT_ID)"
	test -n "$(ASSESSMENT_ID)"
	test -n "$(OUTPUT)"
	$(PYTHON) scripts/sno_trial_dns_delegation.py collect \
		--project-id "$(PROJECT_ID)" \
		--assessment-id "$(ASSESSMENT_ID)" \
		--output "$(OUTPUT)"

verify-sno-trial-dns-delegation:
	test -n "$(REPORT)"
	$(PYTHON) scripts/sno_trial_dns_delegation.py verify --report "$(REPORT)"

observe-sno-trial-operator-path:
	test -n "$(PROJECT_ID)"
	test -n "$(SOURCE_CIDR_FILE)"
	test -n "$(INSTALLER)"
	test -n "$(CLIENT)"
	test -n "$(ASSESSMENT_ID)"
	test -n "$(OUTPUT)"
	$(PYTHON) scripts/sno_trial_operator_path.py collect \
		--project-id "$(PROJECT_ID)" \
		--source-cidr-file "$(SOURCE_CIDR_FILE)" \
		--installer "$(INSTALLER)" \
		--client "$(CLIENT)" \
		--assessment-id "$(ASSESSMENT_ID)" \
		--output "$(OUTPUT)"

verify-sno-trial-operator-path:
	test -n "$(REPORT)"
	$(PYTHON) scripts/sno_trial_operator_path.py verify --report "$(REPORT)"

observe-sno-trial-cluster:
	test -n "$(PROJECT_ID)"
	test -n "$(SOURCE_CIDR_FILE)"
	test -n "$(CLIENT)"
	test -n "$(ASSESSMENT_ID)"
	test -n "$(OUTPUT)"
	$(PYTHON) scripts/sno_trial_cluster_observation.py collect \
		--project-id "$(PROJECT_ID)" \
		--source-cidr-file "$(SOURCE_CIDR_FILE)" \
		--client "$(CLIENT)" \
		--assessment-id "$(ASSESSMENT_ID)" \
		--output "$(OUTPUT)"

verify-sno-trial-cluster:
	test -n "$(REPORT)"
	$(PYTHON) scripts/sno_trial_cluster_observation.py verify \
		--report "$(REPORT)"

observe-sno-trial-resource-exposure:
	test -n "$(TARGET_PROJECT_ID)"
	test -n "$(OPERATOR_PROJECT_ID)"
	test -n "$(OPERATOR_INSTANCE_NAME)"
	test -n "$(PHASE)"
	test -n "$(ASSESSMENT_ID)"
	test -n "$(OUTPUT)"
	$(PYTHON) scripts/sno_trial_resource_exposure.py collect \
		--target-project-id "$(TARGET_PROJECT_ID)" \
		--operator-project-id "$(OPERATOR_PROJECT_ID)" \
		--operator-instance-name "$(OPERATOR_INSTANCE_NAME)" \
		--phase "$(PHASE)" \
		--assessment-id "$(ASSESSMENT_ID)" \
		--output "$(OUTPUT)"

verify-sno-trial-resource-exposure:
	test -n "$(REPORT)"
	$(PYTHON) scripts/sno_trial_resource_exposure.py verify \
		--report "$(REPORT)"

observe-sno-trial-operator-inputs:
	test -n "$(CLIENT)"
	test -n "$(KUBECONFIG)"
	test -n "$(PLATFORM_MANIFEST)"
	test -n "$(RUNTIME_MANIFEST)"
	test -n "$(MODEL_MANIFEST)"
	test -n "$(ASSESSMENT_ID)"
	test -n "$(OUTPUT)"
	$(PYTHON) scripts/sno_trial_operator_inputs.py collect \
		--client "$(CLIENT)" \
		--kubeconfig "$(KUBECONFIG)" \
		--platform-manifest "$(PLATFORM_MANIFEST)" \
		--runtime-manifest "$(RUNTIME_MANIFEST)" \
		--model-manifest "$(MODEL_MANIFEST)" \
		--assessment-id "$(ASSESSMENT_ID)" \
		--output "$(OUTPUT)"

verify-sno-trial-operator-inputs:
	test -n "$(REPORT)"
	$(PYTHON) scripts/sno_trial_operator_inputs.py verify \
		--report "$(REPORT)"

observe-sno-trial-dependency-inputs:
	test -n "$(CLIENT)"
	test -n "$(KUBECONFIG)"
	test -n "$(STORAGE_CLASS)"
	test -n "$(ASSESSMENT_ID)"
	test -n "$(OUTPUT)"
	$(PYTHON) scripts/sno_trial_dependency_inputs.py collect \
		--client "$(CLIENT)" \
		--kubeconfig "$(KUBECONFIG)" \
		--storage-class "$(STORAGE_CLASS)" \
		--assessment-id "$(ASSESSMENT_ID)" \
		--output "$(OUTPUT)"

verify-sno-trial-dependency-inputs:
	test -n "$(REPORT)"
	$(PYTHON) scripts/sno_trial_dependency_inputs.py verify \
		--report "$(REPORT)"

materialize-sno-trial-dependency-manifests:
	test -n "$(INPUT_REPORT)"
	test -n "$(STORAGE_CLASS_FILE)"
	test -n "$(OUTPUT_DIR)"
	test -n "$(MATERIALIZATION_ID)"
	test -n "$(MATERIALIZED_AT)"
	$(PYTHON) scripts/materialize_sno_trial_dependency_manifests.py materialize \
		--input-report "$(INPUT_REPORT)" \
		--storage-class-file "$(STORAGE_CLASS_FILE)" \
		--output-dir "$(OUTPUT_DIR)" \
		--materialization-id "$(MATERIALIZATION_ID)" \
		--at "$(MATERIALIZED_AT)"

verify-sno-trial-dependency-materialization:
	test -n "$(DIRECTORY)"
	$(PYTHON) scripts/materialize_sno_trial_dependency_manifests.py verify \
		--directory "$(DIRECTORY)"

observe-sno-trial-dependency-integrity:
	test -n "$(CLIENT)"
	test -n "$(KUBECONFIG)"
	test -n "$(OPENSSL)"
	test -n "$(INPUT_REPORT)"
	test -n "$(MATERIALIZATION_RECEIPT)"
	test -n "$(ASSESSMENT_ID)"
	test -n "$(OBSERVED_AT)"
	test -n "$(OUTPUT)"
	$(PYTHON) scripts/sno_trial_dependency_integrity.py collect \
		--client "$(CLIENT)" \
		--kubeconfig "$(KUBECONFIG)" \
		--openssl "$(OPENSSL)" \
		--input-report "$(INPUT_REPORT)" \
		--materialization-receipt "$(MATERIALIZATION_RECEIPT)" \
		--assessment-id "$(ASSESSMENT_ID)" \
		--observed-at "$(OBSERVED_AT)" \
		--output "$(OUTPUT)"

verify-sno-trial-dependency-integrity:
	test -n "$(REPORT)"
	$(PYTHON) scripts/sno_trial_dependency_integrity.py verify \
		--report "$(REPORT)"

validate-sno-trial-dependency-dry-run-contract:
	$(PYTHON) scripts/sno_trial_dependency_dry_run.py validate-contract

observe-sno-trial-dependency-dry-run:
	test -n "$(CLUSTER_REPORT)"
	test -n "$(CLIENT)"
	test -n "$(KUBECONFIG)"
	test -n "$(DIRECTORY)"
	test -n "$(ASSESSMENT_ID)"
	test -n "$(OBSERVED_AT)"
	test -n "$(OUTPUT)"
	$(PYTHON) scripts/sno_trial_dependency_dry_run.py collect \
		--cluster-report "$(CLUSTER_REPORT)" \
		--client "$(CLIENT)" \
		--kubeconfig "$(KUBECONFIG)" \
		--directory "$(DIRECTORY)" \
		--assessment-id "$(ASSESSMENT_ID)" \
		--observed-at "$(OBSERVED_AT)" \
		--output "$(OUTPUT)"

verify-sno-trial-dependency-dry-run:
	test -n "$(REPORT)"
	$(PYTHON) scripts/sno_trial_dependency_dry_run.py verify \
		--report "$(REPORT)"

observe-sno-trial-product-dry-run:
	test -n "$(CLUSTER_REPORT)"
	test -n "$(CLIENT)"
	test -n "$(KUBECONFIG)"
	test -n "$(PLATFORM_MANIFEST)"
	test -n "$(RUNTIME_MANIFEST)"
	test -n "$(MODEL_MANIFEST)"
	test -n "$(ASSESSMENT_ID)"
	test -n "$(OUTPUT)"
	$(PYTHON) scripts/sno_trial_product_dry_run.py collect \
		--cluster-report "$(CLUSTER_REPORT)" \
		--client "$(CLIENT)" \
		--kubeconfig "$(KUBECONFIG)" \
		--platform-manifest "$(PLATFORM_MANIFEST)" \
		--runtime-manifest "$(RUNTIME_MANIFEST)" \
		--model-manifest "$(MODEL_MANIFEST)" \
		--assessment-id "$(ASSESSMENT_ID)" \
		--output "$(OUTPUT)"

verify-sno-trial-product-dry-run:
	test -n "$(REPORT)"
	$(PYTHON) scripts/sno_trial_product_dry_run.py verify \
		--report "$(REPORT)"

create-sno-trial-render-admission:
	test -n "$(READINESS)"
	test -n "$(NETWORK)"
	test -n "$(DNS)"
	test -n "$(OPERATOR_PATH)"
	test -n "$(TOOLCHAIN)"
	test -n "$(LEASE)"
	test -n "$(PROJECT_ID)"
	test -n "$(ADMISSION_ID)"
	test -n "$(OUTPUT)"
	$(PYTHON) scripts/sno_trial_install_admission.py create \
		--readiness "$(READINESS)" \
		--network "$(NETWORK)" \
		--dns "$(DNS)" \
		--operator-path "$(OPERATOR_PATH)" \
		--toolchain "$(TOOLCHAIN)" \
		--lease "$(LEASE)" \
		--project-id "$(PROJECT_ID)" \
		--admission-id "$(ADMISSION_ID)" \
		--output "$(OUTPUT)"

verify-sno-trial-render-admission:
	test -n "$(ADMISSION)"
	test -n "$(LEASE)"
	test -n "$(PROJECT_ID)"
	$(PYTHON) scripts/sno_trial_install_admission.py verify \
		--admission "$(ADMISSION)" \
		--lease "$(LEASE)" \
		--project-id "$(PROJECT_ID)"

materialize-sno-trial-install-config:
	test -n "$(RENDERED)"
	test -n "$(PULL_SECRET)"
	test -n "$(SSH_PUBLIC_KEY)"
	test -n "$(LEASE)"
	test -n "$(ADMISSION)"
	test -n "$(PROJECT_ID)"
	test -n "$(OUTPUT)"
	$(PYTHON) scripts/materialize_sno_trial_install_config.py \
		--rendered "$(RENDERED)" \
		--pull-secret "$(PULL_SECRET)" \
		--ssh-public-key "$(SSH_PUBLIC_KEY)" \
		--lease "$(LEASE)" \
		--admission "$(ADMISSION)" \
		--project-id "$(PROJECT_ID)" \
		--output "$(OUTPUT)"

inspect-sno-trial-toolchain:
	test -n "$(ARCHIVE_DIR)"
	test -n "$(INTAKE_ID)"
	test -n "$(OUTPUT)"
	$(PYTHON) scripts/openshift_toolchain_intake.py inspect \
		--directory "$(ARCHIVE_DIR)" \
		--intake-id "$(INTAKE_ID)" \
		--output "$(OUTPUT)"

verify-sno-trial-toolchain:
	test -n "$(REPORT)"
	$(PYTHON) scripts/openshift_toolchain_intake.py verify --report "$(REPORT)"

replay-sno-trial-product-artifacts:
	test -n "$(VERIFICATION_ID)"
	test -n "$(GENERATED_AT)"
	test -n "$(VERIFIER_REVISION)"
	test -n "$(VERIFIER_RUN_ID)"
	test -n "$(OUTPUT)"
	$(PYTHON) scripts/sno_trial_product_artifacts.py replay \
		--verification-id "$(VERIFICATION_ID)" \
		--generated-at "$(GENERATED_AT)" \
		--verifier-revision "$(VERIFIER_REVISION)" \
		--verifier-run-id "$(VERIFIER_RUN_ID)" \
		--verifier-run-attempt 1 \
		--output "$(OUTPUT)"

verify-sno-trial-product-artifacts:
	test -n "$(REPORT)"
	$(PYTHON) scripts/sno_trial_product_artifacts.py verify --report "$(REPORT)"

plan-sno-trial-product-admission-environment:
	test -n "$(TOKEN_FILE)"
	test -n "$(REVIEWER_LOGIN)"
	test -n "$(OUTPUT)"
	$(PYTHON) scripts/configure_sno_trial_product_admission_environment.py plan \
		--token-file "$(TOKEN_FILE)" \
		--reviewer-login "$(REVIEWER_LOGIN)" \
		--output "$(OUTPUT)"

apply-sno-trial-product-admission-environment:
	test -n "$(TOKEN_FILE)"
	test -n "$(REVIEWER_LOGIN)"
	test -n "$(PLAN)"
	test -n "$(EXPECTED_PLAN_DIGEST)"
	$(PYTHON) scripts/configure_sno_trial_product_admission_environment.py apply \
		--token-file "$(TOKEN_FILE)" \
		--reviewer-login "$(REVIEWER_LOGIN)" \
		--plan "$(PLAN)" \
		--expected-plan-digest "$(EXPECTED_PLAN_DIGEST)"

verify-sno-trial-product-admission-environment:
	test -n "$(TOKEN_FILE)"
	$(PYTHON) scripts/configure_sno_trial_product_admission_environment.py verify \
		--token-file "$(TOKEN_FILE)"

plan-reference-lab-environment:
	test -n "$(CONTRACT)"
	test -n "$(TOKEN_FILE)"
	test -n "$(REVIEWER_LOGIN)"
	test -n "$(OUTPUT)"
	$(PYTHON) scripts/configure_reference_lab_environment.py plan \
		--contract "$(CONTRACT)" \
		--token-file "$(TOKEN_FILE)" \
		--reviewer-login "$(REVIEWER_LOGIN)" \
		--output "$(OUTPUT)"

apply-reference-lab-environment:
	test -n "$(CONTRACT)"
	test -n "$(TOKEN_FILE)"
	test -n "$(REVIEWER_LOGIN)"
	test -n "$(PLAN)"
	test -n "$(EXPECTED_PLAN_DIGEST)"
	$(PYTHON) scripts/configure_reference_lab_environment.py apply \
		--contract "$(CONTRACT)" \
		--token-file "$(TOKEN_FILE)" \
		--reviewer-login "$(REVIEWER_LOGIN)" \
		--plan "$(PLAN)" \
		--expected-plan-digest "$(EXPECTED_PLAN_DIGEST)"

verify-reference-lab-environment:
	test -n "$(CONTRACT)"
	test -n "$(TOKEN_FILE)"
	$(PYTHON) scripts/configure_reference_lab_environment.py verify \
		--contract "$(CONTRACT)" \
		--token-file "$(TOKEN_FILE)"

verify-sno-trial-product-admission:
	test -n "$(REPORT)"
	test -n "$(ADMISSION)"
	$(PYTHON) scripts/sno_trial_product_artifact_admission.py verify \
		--report "$(REPORT)" \
		--admission "$(ADMISSION)"

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
