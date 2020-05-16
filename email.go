package main

// NOTE:
// https://github.com/tangingw/go_smtp/blob/master/send_mail.go

import (
	"os"

	"gopkg.in/gomail.v2"
)

var (
	SMTP_SERVER = os.Getenv("SMTP_SERVER")
)

type Sender struct {
	User     string
	Password string
}

func NewSender(Username, Password string) Sender {
	return Sender{
		Username,
		Password,
	}
}

func (sender Sender) SendMail(recipients []string, subject string, body string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", "noreply@mills.io")
	m.SetHeader("To", recipients...)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	d := gomail.NewDialer(SMTP_SERVER, 587, sender.User, sender.Password)

	return d.DialAndSend(m)
}
