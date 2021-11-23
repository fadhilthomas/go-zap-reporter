package config

var base = mergeConfig(
	fileLocationConfig,
	hostConfig,
	logLevelConfig,
	notionDatabaseConfig,
	notionTokenConfig,
	slackConfig,
)
