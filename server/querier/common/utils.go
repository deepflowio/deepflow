package common

import (
	"bufio"
	"io/ioutil"
	"os"
	"strings"
)

func IsValueInSliceString(value string, list []string) bool {
	for _, item := range list {
		if value == item {
			return true
		}
	}
	return false
}

func LoadDbDescriptions(dir string) (map[string]interface{}, error) {
	dbDescriptions := make(map[string]interface{})
	err := readDir(dir, dbDescriptions)
	if err != nil {
		return nil, err
	}
	return dbDescriptions, nil
}

func readDir(dir string, desMap map[string]interface{}) error {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		// TODO
		return err
	}
	for _, fi := range files {
		fileName := dir + "/" + fi.Name()
		if fi.IsDir() {
			dirMap := make(map[string]interface{})
			desMap[fi.Name()] = dirMap
			err := readDir(fileName, dirMap)
			if err != nil {
				return err
			}
		} else {
			desMap[fi.Name()], err = readFile(fileName)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func readFile(fileName string) ([][]interface{}, error) {
	file, err := os.Open(fileName)
	if err != nil {
		//TODO
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	data := make([][]interface{}, 0)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if line == "" || line[:1] == "#" {
			continue
		}
		lineSlice := make([]interface{}, 0)
		for _, split := range strings.Split(line, ",") {
			lineSlice = append(lineSlice, strings.TrimSpace(split))
		}
		data = append(data, lineSlice)
	}
	return data, nil
}
