package chiapos_go

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/spf13/afero"
	"io"
	"math/big"
)

// 19 bytes  - "Proof of Space Plot" (utf-8)
// 32 bytes  - unique plot id
// 1 byte    - k
// 2 bytes   - format description length
// x bytes   - format description
// 2 bytes   - memo length
// x bytes   - memo

type DiskProver struct {
	filePath           string
	k                  uint32
	tableBeginPointers []uint64
	c2                 []uint64
}

func NewDiskProver(filePath string) (*DiskProver, error) {

	var (
		k uint32
	)

	fs := afero.NewOsFs()
	file, err := fs.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("read plot file error: %w", err)
	}
	defer file.Close()

	startSeek := int64(len(plotHeader) + plotIdLen)
	// get k
	kByte := make([]byte, 1)
	_, err = file.ReadAt(kByte, startSeek)
	if err != nil {
		return nil, fmt.Errorf("read k size error: %w", err)
	}
	k = uint32(new(big.Int).SetBytes(kByte).Int64())
	startSeek += 1

	// read format description length
	tmp2Bytes := make([]byte, 2)
	formatDescLenBytes := tmp2Bytes
	_, err = file.ReadAt(formatDescLenBytes, startSeek)
	if err != nil {
		return nil, fmt.Errorf("read format description length error: %w", err)
	}
	formatDescLen := new(big.Int).SetBytes(formatDescLenBytes).Int64()
	// read memo length
	startSeek += 2 + formatDescLen
	memoLenBytes := tmp2Bytes
	_, err = file.ReadAt(memoLenBytes, startSeek)
	if err != nil {
		return nil, fmt.Errorf("read momo length error: %w", err)
	}
	memoLen := new(big.Int).SetBytes(memoLenBytes).Int64()
	startSeek += 2 + memoLen

	// seek
	_, err = file.Seek(startSeek, io.SeekStart)
	if err != nil {
		return nil, err
	}
	// c2
	tableBeginPointers := make([]uint64, 11)
	C2 := make([]uint64, 0)

	for i := 1; i < 11; i++ {
		pointerBuf := make([]byte, 8)
		_, err = file.Read(pointerBuf)
		if err != nil {
			return nil, err
		}
		tableBeginPointers[i] = new(big.Int).SetBytes(pointerBuf).Uint64()
	}
	_, err = file.Seek(int64(tableBeginPointers[9]), io.SeekStart)
	if err != nil {
		return nil, err
	}

	var c2Size = byteAlign(k) / 8
	var c2Entries = uint32(tableBeginPointers[10]-tableBeginPointers[9]) / c2Size

	if c2Entries == 0 || c2Entries == 1 {
		return nil, errors.New("Invalid C2 table size ")
	}

	c2Buf := make([]byte, c2Size)
	for i := 0; i < int(c2Entries)-1; i++ {
		_, err = file.Read(c2Buf)
		if err != nil {
			return nil, err
		}
		b := new(big.Int).SetBytes(c2Buf)
		b = Trunc(b, 0, 25, int(c2Size*8))
		C2 = append(C2, b.Uint64())
	}
	return &DiskProver{
		filePath:           filePath,
		k:                  k,
		tableBeginPointers: tableBeginPointers,
		c2:                 C2,
	}, nil
}

func (dp *DiskProver) GetQualitiesForChallenge(challenge []byte) ([]*big.Int, error) {
	return dp.GetP7Entries(challenge)
}

func (dp *DiskProver) GetP7Entries(challenge []byte) ([]*big.Int, error) {
	fs := afero.NewOsFs()
	file, err := fs.Open(dp.filePath)
	if err != nil {
		return nil, fmt.Errorf("read plot file error: %w", err)
	}
	defer file.Close()

	if dp.c2 == nil || len(dp.c2) == 0 {
		return nil, nil
	}

	f7 := new(big.Int).SetBytes(challenge)
	f7 = Trunc(f7, 0, int(dp.k), 256)

	var (
		c1Index, c2EntryF uint64
		broke             bool
	)

	for _, c2Entry := range dp.c2 {
		c2EntryF = c2Entry
		if f7.Uint64() < c2Entry {
			c1Index -= uint64(kCheckpoint2Interval)
			broke = true
			break
		}
		c1Index += uint64(kCheckpoint2Interval)
	}
	if c1Index < 0 {
		return nil, nil
	}

	if !broke {
		c1Index -= uint64(kCheckpoint2Interval)
	}

	c1EntrySize := byteAlign(dp.k) / 8

	c1EntryBytes := make([]byte, c1EntrySize)
	_, err = file.Seek(int64(dp.tableBeginPointers[8]+(c1Index*uint64(byteAlign(dp.k))/8)), io.SeekStart)
	if err != nil {
		return nil, err
	}

	currF7, prevF7 := c2EntryF, c2EntryF

	for s := 0; s < kCheckpoint1Interval; s++ {
		_, err = file.Read(c1EntryBytes)
		if err != nil {
			return nil, err
		}
		c1Entry := new(big.Int).SetBytes(c1EntryBytes)
		// BIts(x, y/8, y)
		c1Entry = Trunc(c1Entry, 0, 25, int(byteAlign(dp.k)))
		readF7 := c1Entry.Uint64()
		if s != 0 && readF7 == 0 {
			break
		}
		currF7 = readF7

		if f7.Uint64() < currF7 {
			currF7 = prevF7
			c1Index -= 1
			broke = true
			break
		}
		c1Index += 1
		prevF7 = currF7
	}
	if !broke {
		c1Index -= 1
	}
	var (
		c3EntrySize = calculateC2Size(int32(dp.k))
		bitMask     = make([]byte, c3EntrySize)
		doubleEntry = f7.Uint64() == currF7 && c1Index > 0
		//nextF7         uint64
		encodedSizeBuf = make([]byte, 2)
		p7Positions    = make([]uint64, 0)
		currP7Pos      = c1Index * uint64(kCheckpoint2Interval)
	)

	if doubleEntry {
		// todo
		//c1Index -= 1
		//_, err = file.Seek(int64(dp.tableBeginPointers[8])+int64(c1Index)*int64(byteAlign(dp.k))/8, io.SeekStart)
		//if err != nil {
		//	return nil, err
		//}
		//_, err = file.Read(c1EntryBytes)
		//if err != nil {
		//	return nil, err
		//}
		//c1EntryBits := new(big.Int).SetBytes(c1EntryBytes)
		//c1EntryBits = Trunc(c1EntryBits, 0, 25, int(byteAlign(dp.k)))
		//nextF7 = currF7
		//currF7 = c1EntryBits.Uint64()
		//
		//_, err = file.Seek(int64(dp.tableBeginPointers[10])+int64(c1Index)*int64(c3EntrySize), io.SeekStart)
		//if err != nil {
		//	return nil, err
		//}
		//
		//_, err = file.Read(encodedSizeBuf)
		//if err != nil {
		//	return nil, err
		//}
		//encodedSize := new(big.Int).SetBytes(encodedSizeBuf).Uint64()
		//_, err = file.Read(bitMask[:c3EntrySize-2])
		//if err != nil {
		//	return nil, err
		//}
		//c1Index += 1
		//currP7Pos = c1Index + kCheckpoint1Interval
		//secondPositions, err := dp.GetP7Positions(nextF7, f7, currP7Pos, bitMask, encodedSize, c1Index)
		//if err != nil {
		//	return nil, err
		//}
		//
		//p7_positions.insert(
		//	p7_positions.end(), second_positions.begin(), second_positions.end());

	} else {
		_, err = file.Seek(int64(dp.tableBeginPointers[10]+c1Index*uint64(c3EntrySize)), io.SeekStart)
		if err != nil {
			return nil, err
		}

		_, err = file.Read(encodedSizeBuf[:2])
		if err != nil {
			return nil, err
		}
		encodedSize := new(big.Int).SetBytes(encodedSizeBuf).Uint64()
		_, err = file.Read(bitMask[:c3EntrySize-2])
		if err != nil {
			return nil, err
		}
		p7Positions, err = dp.GetP7Positions(currF7, f7.Uint64(), currP7Pos, bitMask, encodedSize, c1Index)
		if err != nil {
			return nil, err
		}
	}
	if len(p7Positions) == 0 {
		return nil, nil
	}
	p7ParkSizeBytes := byteAlign((dp.k+1)*uint32(kEntriesPerPark)) / 8

	p7Entries := make([]uint64, 0)
	p7ParkBuf := make([]byte, p7ParkSizeBytes)

	var parkIndex uint64
	if p7Positions[0] == 0 {
		parkIndex = 0
	} else {
		parkIndex = p7Positions[0] / uint64(kEntriesPerPark)
	}
	_, err = file.Seek(int64(dp.tableBeginPointers[7]+parkIndex*uint64(p7ParkSizeBytes)), io.SeekStart)
	if err != nil {
		return nil, err
	}
	_, err = file.Read(p7ParkBuf)
	if err != nil {
		return nil, err
	}
	p7Park := new(big.Int).SetBytes(p7ParkBuf)

	for i := 0; i < int(p7Positions[len(p7Positions)-1]-p7Positions[0]+1); i++ {
		var newParkIndex = p7Positions[i] / uint64(kEntriesPerPark)
		if newParkIndex > parkIndex {
			_, err = file.Seek(int64(dp.tableBeginPointers[7]+newParkIndex*uint64(p7ParkSizeBytes)), io.SeekStart)
			if err != nil {
				return nil, err
			}
			_, err = file.Read(p7ParkBuf)
			if err != nil {
				return nil, err
			}
			p7Park = new(big.Int).SetBytes(p7ParkBuf)
		}
		startBitIndex := uint32(p7Positions[i]) % uint32(kEntriesPerPark) * (dp.k + 1)
		// BIts(x, y/8, y)
		p7Int := Trunc(p7Park, int(startBitIndex), int(startBitIndex+dp.k+1), int(p7ParkSizeBytes)*8)
		p7Entries = append(p7Entries, p7Int.Uint64())
	}
	if p7Entries == nil {
		return nil, nil
	}

	last5Bits := challenge[31] & 0x1f

	qualities := make([]*big.Int, 0)

	for _, position := range p7Entries {
		for tableIndex := 6; tableIndex > 1; tableIndex-- {
			linePoint := dp.readlinePoint(file, tableIndex, int64(position))
			if linePoint == nil {
				return nil, nil
			}
			x, y := LinePointToSquare(linePoint)
			if x < y {
				return nil, nil
			}
			if ((last5Bits >> (tableIndex - 2)) & 1) == 0 {
				position = y
			} else {
				position = x
			}
		}
		newLinePoint := dp.readlinePoint(file, 1, int64(position))
		x1, x2 := LinePointToSquare(newLinePoint)

		hashInput := make([]byte, 32+byteAlign(2*dp.k)/8)

		copy(hashInput, challenge[:32])

		x1Big := new(big.Int).SetUint64(x1)
		x1Big = new(big.Int).Lsh(x1Big, uint(64-2*dp.k))

		x2Big := new(big.Int).SetUint64(x2)
		x2Big = new(big.Int).Lsh(x2Big, uint(64-dp.k))

		x2x1bytes := make([]byte, byteAlign(2*dp.k)/8)
		copy(x2x1bytes[:3], x2Big.Bytes()[:3])
		x2x1bytes[3] = x2Big.Bytes()[3] + x1Big.Bytes()[0]
		copy(x2x1bytes[4:], x1Big.Bytes()[1:])

		copy(hashInput[32:], x2x1bytes)
		hasher := make([]byte, 32)

		hh := sha256.New()
		hh.Write(hashInput)
		hasher = hh.Sum(nil)

		qualities = append(qualities, new(big.Int).SetBytes(hasher))
	}
	return qualities, nil
}

func (dp *DiskProver) GetP7Positions(currF7, f7, currP7Pos uint64, bitMask []byte, encodeSize, c1Index uint64) ([]uint64, error) {
	deltas, err := ANSDecodeDeltas(kCheckpoint1Interval, bitMask, int(encodeSize), 1)
	if err != nil {
		return nil, err
	}
	p7Positions := make([]uint64, 0)
	surpassedF7 := false

	for _, delta := range deltas {
		if currF7 > f7 {
			surpassedF7 = true
			break
		}
		currF7 += uint64(delta)
		currP7Pos += 1

		if currF7 == f7 {
			p7Positions = append(p7Positions, currP7Pos)
		}

		if currP7Pos >= ((c1Index+1)*uint64(kCheckpoint1Interval))-1 || currF7 >= ((1)<<dp.k)-1 {
			break
		}
	}
	if !surpassedF7 {
		return nil, nil
	}
	return p7Positions, nil
}

func (dp *DiskProver) readlinePoint(f afero.File, tableIndex int, position int64) *big.Int {
	parkIndex := position / int64(kEntriesPerPark)
	parKSizeBits := calculateParkSize(dp.k, tableIndex) * 8
	_, err := f.Seek(int64(dp.tableBeginPointers[tableIndex])+int64(parKSizeBits/8)*parkIndex, io.SeekStart)
	if err != nil {
		return nil
	}

	linePointSize := calculateLinePointSize(dp.k)
	linePointBin := make([]byte, linePointSize+7)
	_, err = f.Read(linePointBin[:linePointSize])
	if err != nil {
		return nil
	}
	linePoint := new(big.Int).SetBytes(linePointBin[:linePointSize])

	linePoint = new(big.Int).Rsh(linePoint, uint(int(linePointSize)*8-int(dp.k)*2))

	stubsSizeBits := calculateStubsSize(dp.k) * 8
	stubsBin := make([]byte, stubsSizeBits/8+7)
	_, err = f.Read(stubsBin[:stubsSizeBits/8])
	if err != nil {
		return nil
	}

	maxDeltasSizeBits := calculateMaxDeltasSize(dp.k, int32(tableIndex)) * 8
	deltasBin := make([]byte, maxDeltasSizeBits/8)
	encodedDeltasSizeByes := make([]byte, 2)
	_, err = f.Read(encodedDeltasSizeByes)
	if err != nil {
		return nil
	}
	encodedDeltasSizeByes[0], encodedDeltasSizeByes[1] = encodedDeltasSizeByes[1], encodedDeltasSizeByes[0]
	encodedDeltasSize := new(big.Int).SetBytes(encodedDeltasSizeByes)

	if encodedDeltasSize.Uint64()*8 > uint64(maxDeltasSizeBits) {
		return nil
	}
	var deltas []byte

	if 0x8000&encodedDeltasSize.Uint64() > 0 {
		// todo
		tmp := encodedDeltasSize.Uint64() & 0x7fff
		encodedDeltasSize = new(big.Int).SetUint64(tmp)
		deltas = make([]byte, encodedDeltasSize.Uint64())
		_, err = f.Read(deltas)
		if err != nil {
			return nil
		}
	} else {
		deltasBin = make([]byte, encodedDeltasSize.Uint64())
		_, err = f.Read(deltasBin)
		if err != nil {
			return nil
		}
		r := kRValues[tableIndex-1]
		deltas, err = ANSDecodeDeltas(kEntriesPerPark-1, deltasBin, int(encodedDeltasSize.Uint64()), r)
		if err != nil {
			return nil
		}
	}

	var startBit int32 = 0
	stubSize := dp.k - uint32(kStubMinusBits)
	sumDeltas := 0
	var sumStubs = big.NewInt(0)

	min1 := position % int64(kEntriesPerPark)
	min2 := len(deltas)
	var min int
	if int(min1) < min2 {
		min = int(min1)
	} else {
		min = min2
	}
	for i := 0; i < min; i++ {
		stub := new(big.Int).SetBytes(stubsBin[startBit/8 : startBit/8+8])
		stub = stub.SetUint64(stub.Uint64())
		stub = new(big.Int).Lsh(stub, uint(startBit)%8)
		stub = stub.SetUint64(stub.Uint64())
		stub = new(big.Int).Rsh(stub, 64-uint(stubSize))
		stub = stub.SetUint64(stub.Uint64())

		sumStubs = new(big.Int).Add(sumStubs, stub)
		startBit += int32(stubSize)
		sumDeltas += int(deltas[i])
	}
	bigDelta := new(big.Int).SetUint64(uint64(sumDeltas))
	bigDelta = new(big.Int).Add(new(big.Int).Lsh(bigDelta, uint(stubSize)), sumStubs)

	finalLinePoint := new(big.Int).Add(linePoint, bigDelta)
	return finalLinePoint
}

func LinePointToSquare(index *big.Int) (uint64, uint64) {
	var x uint64 = 0
	for i := 63; i >= 0; i-- {
		var newX uint64 = x + 1<<i

		if index.Cmp(new(big.Int).SetUint64(GetXEnc(newX))) >= 0 {
			x = newX
		}
	}

	return x, new(big.Int).Sub(index, new(big.Int).SetUint64(GetXEnc(x))).Uint64()
}

func GetXEnc(x uint64) uint64 {
	a, b := x, x-1
	if a%2 == 0 {
		a /= 2
	} else {
		b /= 2
	}
	return a * b
}
