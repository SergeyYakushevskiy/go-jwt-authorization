package server

import "github.com/restream/reindexer/v5"

var (
	DbConnection *reindexer.Reindexer
)

func Init(dbConnection *reindexer.Reindexer) {
	DbConnection = dbConnection
}
