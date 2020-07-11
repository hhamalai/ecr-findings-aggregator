package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/organizations"
	"github.com/aws/aws-sdk-go/service/s3"
	"k8s.io/apimachinery/pkg/util/sets"
	"log"
	"os"
	"time"
)

func GetEnvOrDefault(key string, defaultValue string) string {
	value, found := os.LookupEnv(key)
	if !found {
		return defaultValue
	}
	return value
}

type Image struct {
	Tag    string   `json:"tag"`
	Digest string   `json:"digest"`
	Cves   []string `json:"cves"`
}

func (i *Image) AddCVE(cve string) {
	for idx := range i.Cves {
		if i.Cves[idx] == cve {
			return
		}
	}
	i.Cves = append(i.Cves, cve)
}

type Repository struct {
	Images []Image `json:"images"`
	Name   string  `json:"name"`
}

func (r *Repository) AddImage(image Image) {
	r.Images = append(r.Images, image)
}

type Region struct {
	Repositories []Repository `json:"repositories"`
	Region       string       `json:"region"`
}

func (r *Region) AddRepository(repository Repository) {
	r.Repositories = append(r.Repositories, repository)
}

type Account struct {
	AccountName string   `json:"account_name"`
	AccountId   string   `json:"account_id"`
	Regions     []Region `json:"regions"`
}

func (a *Account) AddRegion(region Region) {
	a.Regions = append(a.Regions, region)
}

type Results struct {
	Vulnerabilities map[string]Finding `json:"vulnerabilities"`
	Accounts        []Account          `json:"accounts"`
	UpdatedAt       string             `json:"updated_at"`
}

type Finding struct {
	CVE   ecr.ImageScanFinding `json:"cve"`
	Count int                  `json:"count"`
}

type AccountAndFindings struct {
	Account  Account
	Findings map[string]Finding
}

func getSession(accountID string, role string) (*session.Session, error) {
	sess := session.Must(session.NewSession())
	creds := stscreds.NewCredentials(sess, fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, role))

	sess, err := session.NewSession(&aws.Config{
		Credentials: creds,
	})
	if err != nil {
		fmt.Println(err)
	}
	return sess, err
}

type SessionCtx struct {
	auditAutomation *session.Session
	ecrScanner *session.Session
	orgListingRole *session.Session
}

func fetchECRFindings(ctx SessionCtx, accountID *string, accountName *string, c chan AccountAndFindings) {
	auditAutomationRole := GetEnvOrDefault("AUDIT_AUTOMATION_ROLE", "AuditAutomationRole")
	sess, err := getSession(aws.StringValue(accountID), auditAutomationRole)
	ctx.auditAutomation = sess
	if err != nil {
		fmt.Println(err)
		c <- AccountAndFindings{}
		return
	}
	regions := []string{"eu-west-1", "eu-north-1", "eu-central-1"}
	allFindings := make(map[string]Finding)

	account := Account{
		AccountName: aws.StringValue(accountName),
		AccountId:   aws.StringValue(accountID),
	}

	for _, region := range regions {
		err := processRegion(ctx, region, allFindings, &account)
		if err != nil {
			fmt.Println(err)
		}
	}
	c <- AccountAndFindings{
		Account:  account,
		Findings: allFindings,
	}
}

func processRegion(ctx SessionCtx, region string, allFindings map[string]Finding, account *Account) error {
	config := aws.NewConfig().WithRegion(region)
	ecrSvc := ecr.New(ctx.auditAutomation, config)
	reg := Region{
		Region: region,
	}

	repositories, err := ecrSvc.DescribeRepositories(&ecr.DescribeRepositoriesInput{})
	if err != nil {
		fmt.Println(err)
		return nil
	}
	for _, repository := range repositories.Repositories {
		err := processRepository(ctx, repository, ecrSvc, allFindings, account, &reg)
		if err != nil {
			fmt.Println(err)
		}
	}
	if len(reg.Repositories) > 0 {
		account.AddRegion(reg)
	}

	return nil
}

func processRepository(ctx SessionCtx, repository *ecr.Repository, ecrSvc *ecr.ECR, allFindings map[string]Finding, account *Account, reg *Region) error {
	repo := Repository{
		Name: aws.StringValue(repository.RepositoryName),
	}

	images, err := ecrSvc.ListImages(&ecr.ListImagesInput{
		RepositoryName: repository.RepositoryName,
	})
	if err != nil {
		fmt.Println(err)
		return nil
	}
	for _, imageID := range images.ImageIds {
		// Do not collect images without associated tags
		if aws.StringValue(imageID.ImageTag) == "" {
			continue
		}
		err := processImage(ctx, imageID, ecrSvc, repository, allFindings, account, reg, &repo)
		if err != nil {
			fmt.Println(err)
		}
	}
	if len(repo.Images) > 0 {
		reg.AddRepository(repo)
	}

	return nil
}

func processImage(ctx SessionCtx, imageID *ecr.ImageIdentifier, ecrSvc *ecr.ECR, repository *ecr.Repository, allFindings map[string]Finding, account *Account, reg *Region, repo *Repository) error {

	image := Image{
		Tag:    aws.StringValue(imageID.ImageTag),
		Digest: aws.StringValue(imageID.ImageDigest),
	}

	findings, err := ecrSvc.DescribeImageScanFindings(&ecr.DescribeImageScanFindingsInput{
		ImageId:        imageID,
		RepositoryName: repository.RepositoryName,
	})
	if err != nil {
		if err.(awserr.Error).Code() == ecr.ErrCodeScanNotFoundException {
			return nil
		}
		return err
	}

	if findings.ImageScanFindings == nil {
		return nil
	} else if len(findings.ImageScanFindings.Findings) == 0 {
		return nil
	} else if image.Tag == "" {
		return nil
	} else if aws.StringValue(findings.ImageScanStatus.Status) == ecr.ScanStatusFailed {
		return nil
	}

	severeFindings := map[string][]*string{}
	severeFindingCategories := sets.NewString("HIGH", "CRITICAL")

	vulns := sets.String{}
	for _, finding := range findings.ImageScanFindings.Findings {
		if vulns.Has(aws.StringValue(finding.Name)) {
			continue
		} else {
			vulns.Insert(aws.StringValue(finding.Name))
		}
		if severeFindingCategories.Has(aws.StringValue(finding.Severity)) {
			current, found := severeFindings[aws.StringValue(finding.Severity)]
			if !found {
				current = []*string{
					finding.Name,
				}
			} else {
				current = append(current, finding.Name)
			}

			severeFindings[aws.StringValue(finding.Severity)] = current
		}

		if _, exists := allFindings[aws.StringValue(finding.Name)]; !exists {
			allFindings[aws.StringValue(finding.Name)] = Finding{
				*finding,
				1,
			}
		} else {
			current := allFindings[aws.StringValue(finding.Name)]
			allFindings[aws.StringValue(finding.Name)] = Finding{
				CVE:   current.CVE,
				Count: current.Count + 1,
			}
		}
		image.AddCVE(aws.StringValue(finding.Name))
	}

	if len(severeFindings) > 0 {
		err = updateDynamodbFindingSummary(ctx, image, account, reg, repository, severeFindings)
		if err != nil {
			fmt.Println(err)
		}
	}

	repo.AddImage(image)

	return nil
}

func updateDynamodbFindingSummary(ctx SessionCtx, image Image, account *Account, reg *Region, repository *ecr.Repository, severeFindings map[string][]*string) error {
	dynamodbSvc := dynamodb.New(ctx.ecrScanner)
	containerImageVulnerabilitiesTable := GetEnvOrDefault("DYNAMODB_TABLE", "dynamodb-vulnerabilities-table")
	convertedFindings := map[string]*dynamodb.AttributeValue{}
	for k, v := range severeFindings {
		convertedFindings[k] = &dynamodb.AttributeValue{
			SS:    v,
		}
	}
	_, err := dynamodbSvc.PutItem(&dynamodb.PutItemInput{
		Item: map[string]*dynamodb.AttributeValue{
			"sha_digest": {
				S: aws.String(image.Digest),
			},
			"tag": {
				S: aws.String(image.Tag),
			},
			"account": {
				S: aws.String(account.AccountId),
			},
			"account_name": {
				S: aws.String(account.AccountName),
			},
			"region": {
				S: aws.String(reg.Region),
			},
			"repository": {
				S: repository.RepositoryName,
			},
			"severe_findings": {
				M: convertedFindings,
			},
			"last_run": {
				S: aws.String(time.Now().String()),
			},
		},
		TableName: aws.String(containerImageVulnerabilitiesTable),
	})

	if err != nil {
		fmt.Println(err)
		return err
	}
	return nil
}

func handler() {
	ecrScannerRole := session.Must(session.NewSession())
	masterAccountId := GetEnvOrDefault("MASTER_ACCOUNT_ID", "0000000000000")
	accountListingRole := GetEnvOrDefault("ACCOUNT_LISTING_ROLE", "AccountsListingRole")
	orgListingRole, _ := getSession(masterAccountId, accountListingRole)

	ctx := SessionCtx{
		orgListingRole: orgListingRole,
		auditAutomation: nil,
		ecrScanner:      ecrScannerRole,
	}

	orgSrv := organizations.New(ctx.orgListingRole)

	resultChannel := make(chan AccountAndFindings)
	var accounts []Account
	childs := 0
	err := orgSrv.ListAccountsPages(&organizations.ListAccountsInput{}, func(page *organizations.ListAccountsOutput, lastPage bool) bool {
		for _, account := range page.Accounts {
			if aws.StringValue(account.Status) == "ACTIVE" {
				childs = childs + 1
				go func(accountId *string, accountName *string) {
					fetchECRFindings(ctx, accountId, accountName, resultChannel)
				}(account.Id, account.Name)

			}
		}
		return !lastPage
	})

	if err != nil {
		log.Panic(err)
	}

	vulns := make(map[string]Finding, 0)
	for childs > 0 {
		accountAndFindings := <-resultChannel
		account := accountAndFindings.Account
		if account.AccountId != "" {
			accounts = append(accounts, account)
		}
		for _, vuln := range accountAndFindings.Findings {
			vulns[aws.StringValue(vuln.CVE.Name)] = vuln
		}
		childs = childs - 1
	}

	results, _ := json.Marshal(Results{
		Accounts:        accounts,
		Vulnerabilities: vulns,
		UpdatedAt:       time.Now().UTC().Format("2006-01-02 15:04:05"),
	})

	s3Svc := s3.New(ctx.ecrScanner)
	S3Bucket := GetEnvOrDefault("S3_BUCKET", "s3-ecr-findings")
	S3Key := GetEnvOrDefault("S3_KEY", "findings.json")
	_, err = s3Svc.PutObject(&s3.PutObjectInput{
		Bucket: aws.String(S3Bucket),
		Key:    aws.String(S3Key),
		Body:   bytes.NewReader(results),

	})
	if err != nil {
		fmt.Println(err)
		log.Panic(err)
	}
}

func main() {
	lambda.Start(handler)
}