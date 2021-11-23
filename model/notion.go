package model

import (
	"context"
	"github.com/fadhilthomas/go-zap-reporter/config"
	"github.com/jomei/notionapi"
	"github.com/pkg/errors"
)

func OpenNotionDB() (client *notionapi.Client) {
	notionToken := config.GetStr(config.NOTION_TOKEN)
	client = notionapi.NewClient(notionapi.Token(notionToken))
	return client
}

func QueryNotionVulnerabilityName(client *notionapi.Client, vulnerability Vulnerability) (output []notionapi.Page, err error) {
	databaseId := config.GetStr(config.NOTION_DATABASE)

	var pageList []notionapi.Page
	var cursor notionapi.Cursor
	for hasMore := true; hasMore; {
		databaseQueryRequest := &notionapi.DatabaseQueryRequest{
			CompoundFilter: &notionapi.CompoundFilter{
				notionapi.FilterOperatorAND: []notionapi.PropertyFilter{
					{
						Property: "Name",
						Text: &notionapi.TextFilterCondition{
							Equals: vulnerability.Name,
						},
					},
					{
						Property: "Host",
						Select: &notionapi.SelectFilterCondition{
							Equals: vulnerability.Host,
						},
					},
					{
						Property: "Endpoint",
						Text: &notionapi.TextFilterCondition{
							Equals: vulnerability.Endpoint,
						},
					},
				},
			},
			StartCursor: cursor,
		}
		resp, err := client.Database.Query(context.Background(), notionapi.DatabaseID(databaseId), databaseQueryRequest)
		if err != nil {
			return nil, errors.New(err.Error())
		}
		pageList = append(pageList, resp.Results...)
		hasMore = resp.HasMore
		cursor = resp.NextCursor
	}
	return pageList, nil
}

func QueryNotionVulnerabilityStatus(client *notionapi.Client, vulnerabilityHost string, vulnerabilityStatus string) (output []notionapi.Page, err error) {
	databaseId := config.GetStr(config.NOTION_DATABASE)

	var pageList []notionapi.Page
	var cursor notionapi.Cursor
	for hasMore := true; hasMore; {
		databaseQueryRequest := &notionapi.DatabaseQueryRequest{
			CompoundFilter: &notionapi.CompoundFilter{
				notionapi.FilterOperatorAND: []notionapi.PropertyFilter{
					{
						Property: "Host",
						Select: &notionapi.SelectFilterCondition{
							Equals: vulnerabilityHost,
						},
					},
					{
						Property: "Status",
						Select: &notionapi.SelectFilterCondition{
							Equals: vulnerabilityStatus,
						},
					},
				},
			},
			StartCursor: cursor,
		}
		resp, err := client.Database.Query(context.Background(), notionapi.DatabaseID(databaseId), databaseQueryRequest)
		if err != nil {
			return nil, errors.New(err.Error())
		}
		pageList = append(pageList, resp.Results...)
		hasMore = resp.HasMore
		cursor = resp.NextCursor
	}
	return pageList, nil
}

func InsertNotionVulnerability(client *notionapi.Client, vulnerability Vulnerability) (output *notionapi.Page, err error) {
	databaseId := config.GetStr(config.NOTION_DATABASE)

	pageInsertQuery := &notionapi.PageCreateRequest{
		Parent: notionapi.Parent{
			DatabaseID: notionapi.DatabaseID(databaseId),
		},
		Properties: notionapi.Properties{
			"Name": notionapi.TitleProperty{
				Title: []notionapi.RichText{
					{
						Text: notionapi.Text{
							Content: vulnerability.Name,
						},
					},
				},
			},
			"Severity": notionapi.SelectProperty{
				Select: notionapi.Option{
					Name: vulnerability.Severity,
				},
			},
			"Host": notionapi.SelectProperty{
				Select: notionapi.Option{
					Name: vulnerability.Host,
				},
			},
			"Endpoint": notionapi.RichTextProperty{
				RichText: []notionapi.RichText{
					{
						Text: notionapi.Text{
							Content: vulnerability.Endpoint,
						},
					},
				},
			},
			"Status": notionapi.SelectProperty{
				Select: notionapi.Option{
					Name: "open",
				},
			},
		},
	}

	res, err := client.Page.Create(context.Background(), pageInsertQuery)
	if err != nil {
		return nil, errors.New(err.Error())
	}
	return res, nil
}

func UpdateNotionVulnerabilityStatus(client *notionapi.Client, pageId string, status string) (output *notionapi.Page, err error) {
	pageUpdateQuery := &notionapi.PageUpdateRequest{
		Properties: notionapi.Properties{
			"Status": notionapi.SelectProperty{
				Select: notionapi.Option{
					Name: status,
				},
			},
		},
	}

	res, err := client.Page.Update(context.Background(), notionapi.PageID(pageId), pageUpdateQuery)
	if err != nil {
		return nil, errors.New(err.Error())
	}
	return res, nil
}
