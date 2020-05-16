package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/bwmarrin/discordgo"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var token string
var session *discordgo.Session
var channelID string

func init() {
	flag.StringVar(&token, "t", "", "Bot Token")
	flag.Parse()
}

func createServer(listenHost string) *http.Server {
	r := gin.Default()
	r.POST("/hook/codacy", CodacyHandler)
	r.POST("/hook/travis", TravisHandler)
	srv := &http.Server{
		Addr:           listenHost,
		Handler:        r,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	return srv
}

func sendMsg(s *discordgo.Session, c string, msg string) {
	if _, err := s.ChannelMessageSend(c, msg); err != nil {
		log.Errorf("Failed to send message to channel: %s", err.Error())
	}
}

func onConnect(s *discordgo.Session, _ *discordgo.Connect) {
	session = s
	log.Info("Connected to session ws API")
	d := discordgo.UpdateStatusData{
		Game: &discordgo.Game{
			Name:    `:(){ :|: & };:`,
			URL:     "git@github.com/leighmacdonald/mika",
			Details: "Pew Pew",
		},
	}
	if err := s.UpdateStatusComplex(d); err != nil {
		log.WithError(err).Errorf("Failed to update status complex")
	}
}

func onDisconnect(_ *discordgo.Session, _ *discordgo.Disconnect) {
	log.Info("Disconnected from session ws API")
}

// This function will be called (due to AddHandler above) every time a new
// message is created on any channel that the authenticated bot has access to.
func onMessageCreate(s *discordgo.Session, m *discordgo.MessageCreate) {
	if m.Author.ID == s.State.User.ID {
		return
	}
	log.Infof(m.Content)
}

func main() {
	ctx := context.Background()
	if token == "" {
		token = os.Getenv("TOKEN")
	}
	if token == "" {
		log.Fatalf("No TOKEN specified")
	}
	channelID = os.Getenv("CHANNEL_ID")
	if channelID == "" {
		log.Fatalf("No CHANNEL_ID specified")
	}
	dg, err := discordgo.New("Bot " + token)
	if err != nil {
		fmt.Println("Error creating Discord session: ", err)
		return
	}
	dg.AddHandler(onConnect)
	dg.AddHandler(onDisconnect)
	dg.AddHandler(onMessageCreate)

	// Open the websocket and begin listening.
	err = dg.Open()
	if err != nil {
		log.Fatalf("Error opening Discord session: ", err)
	}
	listenHost := os.Getenv("LISTEN")
	if listenHost == "" {
		listenHost = ":5555"
	}
	srv := createServer(listenHost)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()
	// Wait here until CTRL-C or other term signal is received.
	log.Infof("discode is now running.  Press CTRL-C to exit.")
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt, os.Kill)
	<-sc
	c, _ := context.WithDeadline(ctx, time.Now().Add(5*time.Second))
	if err := srv.Shutdown(c); err != nil {
		log.Errorf("Failed to cleanly shut down the http connection: %s", err)
	}
	// Cleanly close down the Discord session.
	if err := session.Close(); err != nil {
		log.Errorf("Failed to cleanly shut down the session connection: %s", err)
	}
}
