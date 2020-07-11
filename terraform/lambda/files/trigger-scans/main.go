package main

import (
	"fmt"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/organizations"
	"os"
	"sync"
)

func GetEnvOrDefault(key string, defaultValue string) string {
	value, found := os.LookupEnv(key)
	if !found {
		return defaultValue
	}
	return value
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

func triggerScans(accountID *string, wg *sync.WaitGroup) error {
	defer wg.Done()
	auditAutomationRole := GetEnvOrDefault("AUDIT_AUTOMATION_ROLE", "AuditAutomationRole")
	sess, err := getSession(aws.StringValue(accountID), auditAutomationRole)
	if err != nil {
		return err
	}
	regions := []string{"eu-west-1", "eu-north-1", "eu-central-1"}

	for _, region := range regions {
		config := aws.NewConfig().WithRegion(region)
		ecrSvc := ecr.New(sess, config)

		repositories, err := ecrSvc.DescribeRepositories(&ecr.DescribeRepositoriesInput{
		})
		if err != nil {
			return err
		}
		for _, repository := range repositories.Repositories {
			images, err := ecrSvc.ListImages(&ecr.ListImagesInput{
				RepositoryName: repository.RepositoryName,
			})
			if err != nil {
				return err
			}
			for _, image := range images.ImageIds {
				fmt.Println(aws.StringValue(repository.RepositoryName), aws.StringValue(image.ImageTag))
				_, err := ecrSvc.StartImageScan(&ecr.StartImageScanInput{
					ImageId:        image,
					RepositoryName: repository.RepositoryName,
				})
				if err != nil {
					fmt.Println(err)
					continue
				}
			}
		}
	}
	return nil
}

func handler() {
	masterAccountId := GetEnvOrDefault("MASTER_ACCOUNT_ID", "0000000000000")
	accountListingRole := GetEnvOrDefault("ACCOUNT_LISTING_ROLE", "AccountsListingRole")
	sess, _ := getSession(masterAccountId, accountListingRole)
	orgSrv := organizations.New(sess)
	var wg sync.WaitGroup
	err := orgSrv.ListAccountsPages(&organizations.ListAccountsInput{}, func(page *organizations.ListAccountsOutput, lastPage bool) bool {
		for _, account := range page.Accounts {
			fmt.Println("Account", aws.StringValue(account.Id))

			if aws.StringValue(account.Status) == "ACTIVE" {
				wg.Add(1)
				fmt.Println("Run for account", aws.StringValue(account.Id))
				go func(accountID *string, accountName *string) {
					err := triggerScans(accountID, &wg)
					if err != nil {
						fmt.Println(err)
					}
				}(account.Id, account.Name)
			}
		}
		return !lastPage
	})
	if err != nil {
		fmt.Println(err)
	}
	wg.Wait()
}

func main() {
	lambda.Start(handler)
}