package chiapos_go

import (
	fse "github.com/chuwt/chiapos-go/c_fse"
	"math"
	"math/big"
)

var plotHeader = []byte("Proof of Space Plot")

var (
	kRValues               = []float64{4.7, 2.75, 2.75, 2.7, 2.6, 2.45}
	kCheckpoint1Interval   = 10000
	kCheckpoint2Interval   = 10000
	kC3BitsPerEntry        = 2.4
	kEntriesPerPark        = 2048
	kStubMinusBits         = 3
	kMaxAverageDeltaTable1 = 5.6
	kMaxAverageDelta       = 3.5
)

/*

 */
const (
	plotIdLen = 32
)

func byteAlign(k uint32) uint32 {
	return k + (8-((k)%8))%8
}

func Trunc(x *big.Int, a, b, k int) *big.Int {
	x.Rsh(x, uint(k-b))
	if a > 0 {
		least := big.NewInt(1)
		least.Lsh(least, uint(b-a))
		x.Mod(x, least)
	}
	return x
}

func ANSDecodeDeltas(numDeltas int, inp []byte, inpSize int, R float64) ([]byte, error) {
	return fse.ANSDecodeDeltas(numDeltas, inp, inpSize, R)
}

func calculateC2Size(k int32) int32 {
	if k < 20 {
		return int32(math.Floor(float64(byteAlign(8*uint32(kCheckpoint1Interval)) / 8)))
	} else {
		return int32(byteAlign(uint32(kC3BitsPerEntry)*uint32(kCheckpoint1Interval))) / 8
	}
}

func calculateParkSize(k uint32, tableIndex int) int32 {
	return calculateLinePointSize(k) + calculateStubsSize(k) + calculateMaxDeltasSize(k, int32(tableIndex))
}

func calculateLinePointSize(k uint32) int32 {
	return int32(byteAlign(2*k)) / 8
}

func calculateStubsSize(k uint32) int32 {
	return int32(byteAlign(uint32(kEntriesPerPark-1)*(k-uint32(kStubMinusBits))) / 8)
}

func calculateMaxDeltasSize(k uint32, tableIndex int32) int32 {
	if tableIndex == 1 {
		return int32(byteAlign(uint32(kEntriesPerPark-1)*uint32(kMaxAverageDeltaTable1)) / 8)
	}
	return int32(byteAlign(uint32(kEntriesPerPark-1)*uint32(kMaxAverageDelta)) / 8)
}
