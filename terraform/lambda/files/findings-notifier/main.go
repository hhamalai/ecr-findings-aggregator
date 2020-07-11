package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"os"
	"strings"
	"sync"

	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"k8s.io/apimachinery/pkg/util/sets"
	"log"
	"net/http"
	"text/template"

	"reflect"
)

type Notification struct {
	Room    string `json:"room"`
	Message string `json:"message"`
}

type Finding struct {
	Title           string `json:"Title"`
	AccountName     string `json:"AccountName"`
	Region          string `json:"Region"`
	Repository      string `json:"Repository"`
	Tag             string `json:"Tag"`
	SHADigest       string `json:"SHADigest"`
	Vulnerabilities string `json:"Vulnerabilities"`
}

func GetEnvOrDefault(key string, defaultValue string) string {
	value, found := os.LookupEnv(key)
	if !found {
		return defaultValue
	}
	return value
}

func formatVulnMap(m map[string]string) string {
	r := ""
	for k, v := range m {
		r = r + k + " " + v + " "
	}
	return r
}

func postUpdate(existingImage bool, metadata map[string]events.DynamoDBAttributeValue, findings map[string]string, wg *sync.WaitGroup) {
	_, DebugMode := os.LookupEnv("DEBUG_MODE")

	defer wg.Done()
	roomName := GetEnvOrDefault("CHAT_ROOM", "SomeRoom")

	title := "Vulnerabilities Detected"
	if existingImage {
		title = "Vulnerabilities Changed"
	}
	finding := Finding{
		Title:           title,
		AccountName:     metadata["account_name"].String(),
		Region:          metadata["region"].String(),
		Repository:      metadata["repository"].String(),
		Tag:             metadata["tag"].String(),
		SHADigest:       metadata["sha_digest"].String(),
		Vulnerabilities: formatVulnMap(findings),
	}

	tmpl, err := template.New("format").Parse(`***{{.Title}}***
***Account:*** {{.AccountName}} ({{.Region}})
***Repository:*** {{.Repository}}:{{.Tag}}
***CVEs:*** {{.Vulnerabilities}}
`)

	if err != nil {
		log.Fatal(err)
	}
	var buf bytes.Buffer
	err = tmpl.Execute(&buf, finding)

	notification := Notification{
		Room:    roomName,
		Message: buf.String(),
	}

	body, err := json.Marshal(notification)
	if err != nil {
		log.Fatalln(err)
	}

	if DebugMode {
		fmt.Println("Debug mode, would print:", string(body))
		return
	}

	BotUrl, found := os.LookupEnv("BOT_URL")
	if !found {
		log.Fatalln("BOT_URL is not set")
	}

	resp, err := http.Post(BotUrl, "application/json", bytes.NewBuffer(body))
	if err != nil {
		log.Fatalln(err)
	}

	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(string(respBody))
}

func newFindingsDiff(newVulns map[string]events.DynamoDBAttributeValue) map[string]string {
	return findingsDiff(newVulns, map[string]events.DynamoDBAttributeValue{})
}

func getStringSet(m map[string]events.DynamoDBAttributeValue, key string) sets.String {
	if _, found := m[key]; found {
		return sets.NewString(m[key].StringSet()...)
	} else {
		return sets.NewString()
	}
}

func findingsDiff(newVulns map[string]events.DynamoDBAttributeValue, oldVulns map[string]events.DynamoDBAttributeValue) map[string]string {

	newCriticals := getStringSet(newVulns, "CRITICAL")
	oldCriticals := getStringSet(oldVulns, "CRITICAL")
	newHigh := getStringSet(newVulns, "HIGH")
	oldHigh := getStringSet(oldVulns, "HIGH")

	criticalsAdded := newCriticals.Difference(oldCriticals)
	criticalsRemoved := oldCriticals.Difference(newCriticals)
	highsAdded := newHigh.Difference(oldHigh)
	highsRemoved := oldHigh.Difference(newHigh)

	result := map[string]string{}
	if criticalsAdded.Len() > 0 {
		result["Critical"] = strings.Join(criticalsAdded.List(), ",")
	}
	if criticalsRemoved.Len() > 0 {
		result["Removed criticals"] = strings.Join(criticalsRemoved.List(), ",")
	}
	if highsAdded.Len() > 0 {
		result["High"] = strings.Join(highsAdded.List(), ",")
	}
	if highsRemoved.Len() > 0 {
		result["Removed highs"] = strings.Join(highsRemoved.List(), ",")
	}
	return result
}

func handler(e events.DynamoDBEvent) error {
	var wg sync.WaitGroup
	for _, record := range e.Records {
		_, found := record.Change.NewImage["severe_findings"]
		if !found {
			continue
		}
		if record.EventName == "INSERT" {
			// New item in table
			imageMetadata := record.Change.NewImage
			wg.Add(1)
			go postUpdate(false, imageMetadata, newFindingsDiff(imageMetadata["severe_findings"].Map()), &wg)
		} else if record.EventName == "MODIFY" {
			// Updates to existing item in table
			newImage := record.Change.NewImage
			oldImage := record.Change.OldImage
			newVulnerabilities := newImage["severe_findings"].Map()
			oldVulnerabilities := oldImage["severe_findings"].Map()
			if !reflect.DeepEqual(newVulnerabilities, oldVulnerabilities) {
				wg.Add(1)
				go postUpdate(true, newImage, findingsDiff(newVulnerabilities, oldVulnerabilities), &wg)
			}
		} else {
			fmt.Println("unknown event")
		}
	}
	wg.Wait()
	return nil
}

func main() {
	lambda.Start(handler)
}
