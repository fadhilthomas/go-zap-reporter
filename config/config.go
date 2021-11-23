package config

var base = mergeConfig(
	fileLocationConfig,
	dastWebsiteConfig,
	logLevelConfig,
	notionDatabaseConfig,
	notionTokenConfig,
	slackConfig,
)
