package magiclinkauth

import (
	"github.com/prologic/bitcask"
)

type MagicLinkAuth struct {
	db *bitcask.Bitcask
}

func NewMagicLinkAuth(db *bitcask.Bitcask) (*MagicLinkAuth, error) {
	return &MagicLinkAuth{
		db: db,
	}, nil
}
