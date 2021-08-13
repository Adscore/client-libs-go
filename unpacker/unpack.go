package unpacker

import (
	"adscore/utils"
	"fmt"
	"regexp"
	"strconv"
)

func Unpack(format string, data []byte) (map[string]interface{}, error) {
	formatPointer := 0
	dataPointer := 0
	resultMap := map[string]interface{}{}
	var instruction string
	var quantifier string
	var quantifierInt int
	var label string
	var currentData []byte
	var currentResult uint
	for formatPointer < len(format) {
		instruction = utils.CharAt(format, formatPointer)
		quantifier = ""
		formatPointer++
		isCharMatches, _ := regexp.Match("[\\d\\*]", []byte(utils.CharAt(format, formatPointer)))
		for formatPointer < len(format) && isCharMatches {
			quantifier = quantifier + utils.CharAt(format, formatPointer)
			formatPointer++
		}
		if quantifier == "" {
			quantifier = "1"
		}
		var labelSb string
		for formatPointer < len(format) && utils.CharAt(format, formatPointer) != "/" {
			labelSb = labelSb + utils.CharAt(format, formatPointer)
			formatPointer++
		}
		label = labelSb
		if utils.CharAt(format, formatPointer) == "/" {
			formatPointer++
		}
		switch instruction {
		case "c":
		case "C":
			if quantifier == "*" {
				quantifierInt = len(data) - dataPointer
			} else {
				quantifierInt, _ = strconv.Atoi(quantifier)
			}

			currentData = data[dataPointer : dataPointer+quantifierInt]
			dataPointer += quantifierInt
			currentDataLength := len(currentData)
			for i := 0; i < currentDataLength; i++ {
				currentResult = uint(currentData[i])

				if (instruction == "c") && (currentResult >= 128) {
					currentResult = currentResult - 256
				}

				key := label
				if quantifierInt > 1 {
					key = fmt.Sprint(key, i+1)
				}
				resultMap[key] = currentResult
			}
		case "n":
			if quantifier == "*" {
				quantifierInt = (len(data) - dataPointer) / 2
			} else {
				quantifierInt, _ = strconv.Atoi(quantifier)
			}

			currentData = data[dataPointer : dataPointer+quantifierInt*2]
			dataPointer = dataPointer + quantifierInt*2
			currentDataLength := len(currentData)
			for i := 0; i < currentDataLength; i += 2 {
				p1 := int(currentData[i]&0xFF) << 8
				p2 := int(currentData[i+1] & 0xFF)
				currentResult = uint(p1 + p2)
				key := label
				if quantifierInt > 1 {
					key = fmt.Sprint(key, (i/2)+1)
				}
				resultMap[key] = currentResult
			}
		case "N":
			if quantifier == "*" {
				quantifierInt = (len(data) - dataPointer) / 4
			} else {
				quantifierInt, _ = strconv.Atoi(quantifier)
			}

			currentData = data[dataPointer : dataPointer+quantifierInt*4]
			dataPointer += quantifierInt * 4
			currentDataLen := len(currentData)
			for i := 0; i < currentDataLen; i += 4 {
				p1 := int(currentData[i]&0xFF) << 24
				p2 := int(currentData[i+1]&0xFF) << 16
				p3 := int(currentData[i+2]&0xFF) << 8
				p4 := int(currentData[i+3])

				currentResult = uint(p1 + p2 + p3 + p4)
				key := label
				if quantifierInt > 1 {
					key = fmt.Sprint(key, (i/4)+1)
				}
				resultMap[key] = currentResult
			}
			//default:
			//return new UnpackResult(
			//String.format("Unknown format code:%s", String.valueOf(instruction)));
			//}
		}

	}
	return resultMap, nil
}
