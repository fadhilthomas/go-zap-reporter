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
)

var (
	notionDatabase      *notionapi.Client
	slackBlockList      []model.SlackBlockBody
	slackAttachmentList []model.SlackAttachmentBody
	severityMap         = map[string]string{
		"0": "info",
		"1": "low",
		"2": "medium",
		"3": "high",
	}
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

	rl := ratelimit.New(1)

	notionDatabase = model.OpenNotionDB()
	rl.Take()
	// find all open entries in repository
	notionQueryStatusResult, err := model.QueryNotionVulnerabilityStatus(notionDatabase, "open")
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

	for _, site := range vulnerabilityOutput.Site {
		summaryReportSeverity.Host = site.Host
		for _, alert := range site.Alerts {
			vulnerability := model.Vulnerability{}
			vulnerability.Name = alert.Name
			vulnerability.Host = site.Host
			vulnerability.Endpoint = alert.Instances[0].URI
			vulnerability.Severity = severityMap[alert.Riskcode]
			vulnerability.CWE = alert.Cweid
			vulnerabilityList = append(vulnerabilityList, vulnerability)

			switch vulnerability.Severity {
			case "high":
				summaryReportSeverity.High++
			case "medium":
				summaryReportSeverity.Medium++
			case "low":
				summaryReportSeverity.Low++
			case "info":
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
	}

	slackBlockList = append(slackBlockList, model.CreateBlockSummary(summaryReportSeverity, summaryReportStatus))
	err = model.SendSlackNotification(slackToken, slackAttachmentList, slackBlockList)
	if err != nil {
		log.Error().Stack().Err(errors.New(err.Error())).Msg("")
		return
	}
}
