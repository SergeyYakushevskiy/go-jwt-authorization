package model

type LoggingConfig struct {
	Dir          string `json:"dir"`
	ConsoleLevel string `json:"console_level"`
	FileLevel    string `json:"log_level"`
}

type DbConfig struct {
	Host   string `json:"host"`
	Port   uint16 `json:"port"`
	DbName string `json:"db_name"`
}

type JwtConfig struct {
	RefreshTokenExpired uint32 `json:"refresh_exp"`
	AccessTokenExpired  uint32 `json:"access_exp"`
}

type HttpConfig struct {
	Host string `json:"host"`
	Port int16  `json:"port"`
}

type Config struct {
	Logging *LoggingConfig `json:"logging"`
	Db      *DbConfig      `json:"db"`
	Http    *HttpConfig    `json:"http"`
	Jwt     *JwtConfig     `json:"jwt"`
}
