all:
	cd lambda/files/collect-findings && GOARCH=amd64 GOOS=linux go build
	cd lambda/files/trigger-scans && GOARCH=amd64 GOOS=linux go build
	cd lambda/files/findings-notifier && GOARCH=amd64 GOOS=linux go build

clean:
	rm files/collect-findings/collect-findings
	rm files/trigger-scans/trigger-scans
	rm files/findings-notifier/findings-notifier
	rm *.zip
