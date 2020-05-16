package main

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
)

type codacy struct {
	Commit struct {
		Data struct {
			UUID string `json:"uuid"`
			Urls struct {
				Delta string `json:"delta"`
			} `json:"urls"`
		} `json:"data"`
		Results struct {
			FixedCount int `json:"fixed_count"`
			NewCount   int `json:"new_count"`
		} `json:"results"`
	} `json:"commit"`
}

func CodacyHandler(c *gin.Context) {
	b, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		log.Errorf("Failed to decode request body: %s", err.Error())
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	defer func() { _ = c.Request.Body.Close() }()
	var cod codacy
	if err := json.Unmarshal(b, &cod); err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	if session != nil {
		msg := fmt.Sprintf("Codacy - Fixed Issues: %d New Issues %d - <%s>",
			cod.Commit.Results.FixedCount, cod.Commit.Results.NewCount, cod.Commit.Data.Urls.Delta)
		sendMsg(session, channelID, msg)
	}
	c.AbortWithStatus(http.StatusOK)
}
