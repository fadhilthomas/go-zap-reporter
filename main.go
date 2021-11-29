package main

import (
	"encoding/json"
	"github.com/fadhilthomas/go-zap-reporter/config"
	"github.com/fadhilthomas/go-zap-reporter/model"
	"github.com/jomei/notionapi"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"
	"go.uber.org/ratelimit"
	"io/ioutil"
	"os"
	"strings"
)

var (
	notionDatabase        *notionapi.Client
	slackBlockList        []model.SlackBlockBody
	slackAttachmentList   []model.SlackAttachmentBody
	vulnerabilityList     []model.Vulnerability
	summaryReportSeverity model.SummaryReportSeverity
	summaryReportStatus   model.SummaryReportStatus
)

func main() {
	config.Set(config.LOG_LEVEL, "info")
	if config.GetStr(config.LOG_LEVEL) == "debug" {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack

	slackToken := config.GetStr(config.SLACK_TOKEN)
	vulnerabilityHost := config.GetStr(config.DAST_WEBSITE)
	if vulnerabilityHost == "" {
		vulnerabilityHost = config.GetStr(config.DAST_API_TARGET_URL)
	}

	rl := ratelimit.New(1)

	notionDatabase = model.OpenNotionDB()
	rl.Take()
	// find all open entries in repository
	notionQueryStatusResult, err := model.QueryNotionVulnerabilityStatus(notionDatabase, vulnerabilityHost, "open")
	if err != nil {
		log.Error().Stack().Err(errors.New(err.Error())).Msg("")
		return
	}
	// set status to close for all entries in repository
	for _, notionPage := range notionQueryStatusResult {
		rl.Take()
		_, err = model.UpdateNotionVulnerabilityStatus(notionDatabase, notionPage.ID.String(), "close")
		if err != nil {
			log.Error().Stack().Err(errors.New(err.Error())).Msg("")
			return
		}
		summaryReportStatus.Close++
	}

	fileReport, err := os.Open(config.GetStr(config.FILE_LOCATION))
	if err != nil {
		log.Error().Stack().Err(errors.New(err.Error())).Msg("")
		return
	}

	byteValue, _ := ioutil.ReadAll(fileReport)
	vulnerabilityOutput := model.Output{}
	err = json.Unmarshal(byteValue, &vulnerabilityOutput)
	if err != nil {
		log.Error().Stack().Err(errors.New(err.Error())).Msg("")
		return
	}

	for _, vulnerabilities := range vulnerabilityOutput.Vulnerabilities {
		summaryReportSeverity.Host = vulnerabilityHost
		vulnerability := model.Vulnerability{}
		vulnerability.Name = strings.TrimSpace(truncateString(vulnerabilities.Message, 100))
		vulnerability.Host = vulnerabilityHost
		if vulnerabilities.Location.Path != "" {
			vulnerability.Endpoint = strings.TrimSpace(truncateString(vulnerabilities.Location.Path, 100))
		} else {
			vulnerability.Endpoint = "/"
		}
		vulnerability.Severity = vulnerabilities.Severity
		vulnerabilityList = append(vulnerabilityList, vulnerability)
	}

	for _, vulnerability := range removeDuplicate(vulnerabilityList) {

		switch vulnerability.Severity {
		case "High":
			summaryReportSeverity.High++
		case "Medium":
			summaryReportSeverity.Medium++
		case "Low":
			summaryReportSeverity.Low++
		case "Info":
			summaryReportSeverity.Info++
		}

		// check existing vulnerability
		rl.Take()
		notionQueryNameResult, err := model.QueryNotionVulnerabilityName(notionDatabase, vulnerability)
		if err != nil {
			log.Error().Stack().Err(errors.New(err.Error())).Msg("")
			return
		}

		// if the vulnerability is new, insert it to notion else update the status
		if len(notionQueryNameResult) > 0 {
			for _, notionPage := range notionQueryNameResult {
				rl.Take()
				_, err = model.UpdateNotionVulnerabilityStatus(notionDatabase, string(notionPage.ID), "open")
				if err != nil {
					log.Error().Stack().Err(errors.New(err.Error())).Msg("")
					return
				}
				summaryReportStatus.Open++
				summaryReportStatus.Close--
			}
		} else {
			rl.Take()
			_, err = model.InsertNotionVulnerability(notionDatabase, vulnerability)
			if err != nil {
				log.Error().Stack().Err(errors.New(err.Error())).Msg("")
				return
			}
			summaryReportStatus.New++
			summaryReportStatus.Open++
		}
	}

	slackBlockList = append(slackBlockList, model.CreateBlockSummary(summaryReportSeverity, summaryReportStatus))
	err = model.SendSlackNotification(slackToken, slackAttachmentList, slackBlockList)
	if err != nil {
		log.Error().Stack().Err(errors.New(err.Error())).Msg("")
		return
	}
}

func removeDuplicate(duplicate []model.Vulnerability) []model.Vulnerability {
	var unique []model.Vulnerability
	type key struct{ value1, value2, value3 string }
	m := make(map[key]int)
	for _, v := range duplicate {
		k := key{v.Name, v.Host, v.Endpoint}
		if i, ok := m[k]; ok {
			unique[i] = v
		} else {
			m[k] = len(unique)
			unique = append(unique, v)
		}
	}
	return unique
}

func truncateString(str string, num int) string {
	bnoden := str
	if len(str) > num {
		if num > 3 {
			num -= 3
		}
		bnoden = str[0:num] + "..."
	}
	return bnoden
}
