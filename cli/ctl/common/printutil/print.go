/*
 * Copyright (c) 2023 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package printutil for output styling.
package printutil

import "fmt"

const (
	textBlack = iota + 30
	textRed
	textGreen
	textYellow
	textBlue
	textMagenta
	textCyan
	textWhite
)

func setColor(msg string, conf, bg, text int) string {
	return fmt.Sprintf("%c[%d;%d;%dm%s%c[0m", 0x1B, conf, bg, text, msg, 0x1B)
}

func yellow(msg string) string {
	return setColor(msg, 0, 0, textYellow)
}

func red(msg string) string {
	return setColor(msg, 0, 0, textRed)
}

// WarnWithColor formats using the deafult formats output and writes standard output in a yellow font.
func WarnWithColor(message string) {
	fmt.Println(yellow("WARNING: " + message))
}

// WarnfWithColor formats according to a format specifier and writes standard output in a yellow font.
func WarnfWithColor(format string, a ...any) {
	format = "WARNING: " + format
	fmt.Println(yellow(fmt.Sprintf(format, a...)))
}

// ErrorWithColor formats using the deafult formats output and writes standard output in a red font.
func ErrorWithColor(message string) {
	fmt.Println(red("ERROR: " + message))
}

// ErrorfWithColor formats according to a format specifier and writes standard output in a error font.
func ErrorfWithColor(format string, a ...any) {
	format = "ERROR: " + format
	fmt.Println(red(fmt.Sprintf(format, a...)))
}
