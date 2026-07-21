PYTHON ?= python3
TERRAFORM ?= terraform

.PHONY: validate test verify-dependency-sources terraform-fmt terraform-validate

validate:
	$(PYTHON) scripts/validate_repository.py
	$(PYTHON) scripts/validate_release_set.py
	$(PYTHON) scripts/validate_dependency_bom.py
	$(PYTHON) scripts/validate_dependency_admission.py
	$(PYTHON) scripts/validate_dependency_supply_chain.py
	kubectl kustomize gitops/clusters/reference-lab | $(PYTHON) scripts/validate_rendered_gitops.py
	kubectl kustomize gitops/dependencies/reference-lab | $(PYTHON) scripts/validate_dependency_gitops.py
	kubectl kustomize gitops/products/reference-lab | $(PYTHON) scripts/validate_product_gitops.py

test:
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v

verify-dependency-sources:
	$(PYTHON) scripts/verify_dependency_sources.py
	$(PYTHON) scripts/verify_dependency_signatures.py

terraform-fmt:
	$(TERRAFORM) fmt -check -recursive infra/terraform

terraform-validate:
	$(TERRAFORM) -chdir=infra/terraform/bootstrap init -backend=false -input=false
	$(TERRAFORM) -chdir=infra/terraform/bootstrap validate
	$(TERRAFORM) -chdir=infra/terraform/foundation init -backend=false -input=false
	$(TERRAFORM) -chdir=infra/terraform/foundation validate
