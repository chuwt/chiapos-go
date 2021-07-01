package chiapos_go

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"math/big"
	"testing"
)

func TestProverDisk(t *testing.T) {
	d, err := NewDiskProver("/Volumes/hdd1000gb/workspace/src/chiapos/plot-k25-2021-06-23-17-06-e96de28bb7ab9fa7e7a4dbce18593d7b199e0f0e0b2cbcdb8f743261603aa510.plot")
	if err != nil {
		log.Fatal(err)
	}
	for i := 1; i < 30; i++ {
		h := sha256.New()
		buf := make([]byte, 32)
		n := big.NewInt(int64(i)).FillBytes(buf)
		h.Write(n)
		challenge := h.Sum(nil)
		qualities, err := d.GetQualitiesForChallenge(challenge)
		if err != nil {
			log.Fatal(err)
		}
		for _, q := range qualities {
			t.Log("challenge", hex.EncodeToString(challenge), q.Bytes(), hex.EncodeToString(q.Bytes()))
		}
	}

}
