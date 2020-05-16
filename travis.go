package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"time"
)

var allowedIP = []string{"54.173.229.200", "54.175.230.252"}

// TravisCI webhook payload https://docs.travis-ci.com/user/notifications/#configuring-webhook-notifications
type TravisCI struct {
	ID     int    `json:"id"`
	Number string `json:"number"`
	Config struct {
		Language string   `json:"language"`
		Os       []string `json:"os"`
		Dist     string   `json:"dist"`
		Branches struct {
			Only []string `json:"only"`
		} `json:"branches"`
		Jobs struct {
			Include []struct {
				Name     string `json:"name"`
				Language string `json:"language"`
				Python   string `json:"python,omitempty"`
				Env      []struct {
					Global string `json:"global"`
				} `json:"env,omitempty"`
				Cache struct {
					Pip         bool     `json:"pip"`
					Directories []string `json:"directories"`
				} `json:"cache"`
				Addons struct {
					Apt struct {
						Packages []string `json:"packages"`
					} `json:"apt"`
				} `json:"addons,omitempty"`
				Install []string `json:"install"`
				Script  []string `json:"script"`
				If      string   `json:"if,omitempty"`
				Deploy  []struct {
					PullRequest bool   `json:"pull_request"`
					Provider    string `json:"provider"`
					Token       struct {
						Secure string `json:"secure"`
					} `json:"token"`
					Branch string `json:"branch"`
					Edge   struct {
						Branch string `json:"branch"`
					} `json:"edge"`
				} `json:"deploy,omitempty"`
			} `json:"include"`
		} `json:"jobs"`
		Notifications struct {
			Slack []struct {
				Rooms []struct {
					Secure string `json:"secure"`
				} `json:"rooms"`
				OnSuccess string `json:"on_success"`
			} `json:"slack"`
			Webhooks []struct {
				Urls []string `json:"urls"`
			} `json:"webhooks"`
		} `json:"notifications"`
	} `json:"config"`
	Type              string      `json:"type"`
	State             string      `json:"state"`
	Status            int         `json:"status"`
	Result            int         `json:"result"`
	StatusMessage     string      `json:"status_message"`
	ResultMessage     string      `json:"result_message"`
	StartedAt         time.Time   `json:"started_at"`
	FinishedAt        time.Time   `json:"finished_at"`
	Duration          int         `json:"duration"`
	BuildURL          string      `json:"build_url"`
	CommitID          int         `json:"commit_id"`
	Commit            string      `json:"commit"`
	BaseCommit        interface{} `json:"base_commit"`
	HeadCommit        interface{} `json:"head_commit"`
	Branch            string      `json:"branch"`
	Message           string      `json:"message"`
	CompareURL        string      `json:"compare_url"`
	CommittedAt       time.Time   `json:"committed_at"`
	AuthorName        string      `json:"author_name"`
	AuthorEmail       string      `json:"author_email"`
	CommitterName     string      `json:"committer_name"`
	CommitterEmail    string      `json:"committer_email"`
	PullRequest       bool        `json:"pull_request"`
	PullRequestNumber interface{} `json:"pull_request_number"`
	PullRequestTitle  interface{} `json:"pull_request_title"`
	Tag               interface{} `json:"tag"`
	Repository        struct {
		ID        int         `json:"id"`
		Name      string      `json:"name"`
		OwnerName string      `json:"owner_name"`
		URL       interface{} `json:"url"`
	} `json:"repository"`
	Matrix []struct {
		ID           int    `json:"id"`
		RepositoryID int    `json:"repository_id"`
		ParentID     int    `json:"parent_id"`
		Number       string `json:"number"`
		State        string `json:"state"`
		Config       struct {
			Os       string `json:"os"`
			Language string `json:"language"`
			Dist     string `json:"dist"`
			Branches struct {
				Only []string `json:"only"`
			} `json:"branches"`
			Name   string        `json:"name"`
			Python string        `json:"python"`
			Env    []interface{} `json:"env"`
			Cache  struct {
				Pip         bool     `json:"pip"`
				Directories []string `json:"directories"`
			} `json:"cache"`
			Addons struct {
				Apt struct {
					Packages []string `json:"packages"`
				} `json:"apt"`
			} `json:"addons"`
			Install []string `json:"install"`
			Script  []string `json:"script"`
		} `json:"config"`
		Status         int         `json:"status"`
		Result         int         `json:"result"`
		Commit         string      `json:"commit"`
		Branch         string      `json:"branch"`
		Message        string      `json:"message"`
		CompareURL     string      `json:"compare_url"`
		StartedAt      time.Time   `json:"started_at"`
		FinishedAt     time.Time   `json:"finished_at"`
		CommittedAt    time.Time   `json:"committed_at"`
		AuthorName     string      `json:"author_name"`
		AuthorEmail    string      `json:"author_email"`
		CommitterName  string      `json:"committer_name"`
		CommitterEmail string      `json:"committer_email"`
		AllowFailure   interface{} `json:"allow_failure"`
	} `json:"matrix"`
}

type ConfigKey struct {
	Config struct {
		Host        string `json:"host"`
		ShortenHost string `json:"shorten_host"`
		Assets      struct {
			Host string `json:"host"`
		} `json:"assets"`
		Pusher struct {
			Key string `json:"key"`
		} `json:"pusher"`
		Github struct {
			APIURL string   `json:"api_url"`
			Scopes []string `json:"scopes"`
		} `json:"github"`
		Notifications struct {
			Webhook struct {
				PublicKey string `json:"public_key"`
			} `json:"webhook"`
		} `json:"notifications"`
	} `json:"config"`
}

func PayloadSignature(r *http.Request) ([]byte, error) {

	signature := r.Header.Get("Signature")
	b64, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return nil, errors.New("cannot decode signature")
	}

	return b64, nil
}

func parsePublicKey(key string) (*rsa.PublicKey, error) {

	// https://golang.org/pkg/encoding/pem/#Block
	block, _ := pem.Decode([]byte(key))

	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("invalid public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid public key")
	}

	return publicKey.(*rsa.PublicKey), nil

}

func TravisPublicKey() (*rsa.PublicKey, error) {
	// NOTE: Use """https://api.travis-ci.com/config""" for private repos.
	response, err := http.Get("https://api.travis-ci.com/config")

	if err != nil {
		return nil, errors.New("cannot fetch travis public key")
	}
	defer response.Body.Close()

	decoder := json.NewDecoder(response.Body)
	var t ConfigKey
	err = decoder.Decode(&t)
	if err != nil {
		return nil, errors.New("cannot decode travis public key")
	}

	key, err := parsePublicKey(t.Config.Notifications.Webhook.PublicKey)
	if err != nil {
		return nil, err
	}

	return key, nil

}

func PayloadDigest(payload string) []byte {
	hash := sha1.New()
	hash.Write([]byte(payload))
	return hash.Sum(nil)

}

func TravisHandler(c *gin.Context) {
	clientIp := c.ClientIP()
	valid := false
	for _, validIP := range allowedIP {
		if clientIp == validIP {
			valid = true
			break
		}
	}
	if !valid {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	key, err := TravisPublicKey()
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	signature, err := PayloadSignature(c.Request)
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	payload := PayloadDigest(c.Request.FormValue("payload"))

	err = rsa.VerifyPKCS1v15(key, crypto.SHA1, payload, signature)

	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	b, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		log.Errorf("Failed to decode request body: %s", err.Error())
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	defer func() { _ = c.Request.Body.Close() }()
	var travis TravisCI
	if err := json.Unmarshal(b, &travis); err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	if session != nil {
		msg := fmt.Sprintf("TravisCI - %s\n %s %s\n%s",
			travis.Message, travis.StatusMessage, travis.CommitterName, travis.BuildURL)
		sendMsg(session, channelID, msg)
	}
	c.AbortWithStatus(http.StatusOK)
}
