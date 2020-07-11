REPOSITORY = <YOUR_ACCOUNT_ID>.dkr.ecr.eu-west-1.amazonaws.com/ecr-cve-dashboard
VERSION = 0.1


all:
	cd terraform; make; terraform apply
	cd web; yarn build
	docker build -t $(REPOSITORY):$(VERSION) .
	aws --region eu-west-1 ecr get-login-password | docker login --username AWS --password-stdin $(REPOSITORY)
	docker push $(REPOSITORY):$(VERSION)
	aws eks update-kubeconfig --name ClusterName
	kubectl apply -f kubernetes/deployment.yaml
