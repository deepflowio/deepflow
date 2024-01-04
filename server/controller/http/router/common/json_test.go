/*
 * Copyright (c) 2024 Yunshan Networks
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

package common

import (
	"reflect"
	"testing"
)

type User struct {
	ID        int        `json:"id"`
	Name      *Name      `json:"name"`
	Emails    []*Email   `json:"emails"`
	IsAdmin   bool       `json:"is_admin"`
	Address   Address    `json:"address"`
	Interests []Interest `json:"interests"`
}

type Name struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

type Email struct {
	Email string `json:"email"`
}

type Address struct {
	City  string `json:"city"`
	State string `json:"state"`
}

type Interest struct {
	Interest string `json:"interest"`
}

type Animal struct {
	Name string `json:"animal_name"`
}

func Test_getAllJSONTags(t *testing.T) {
	type args struct {
		typ    reflect.Type
		tagMap map[string]bool
	}
	tests := []struct {
		name     string
		args     args
		wantTags []string
	}{
		{
			name: "get all tags of the user ptr successfully",
			args: args{
				typ:    reflect.TypeOf(&User{}),
				tagMap: make(map[string]bool),
			},
			wantTags: []string{
				"id", "name", "first_name", "last_name", "emails", "email", "is_admin",
				"address", "city", "state", "interests", "interest",
			},
		},
		{
			name: "get all tags of the user successfully",
			args: args{
				typ:    reflect.TypeOf(User{}),
				tagMap: make(map[string]bool),
			},
			wantTags: []string{
				"id", "name", "first_name", "last_name", "emails", "email", "is_admin",
				"address", "city", "state", "interests", "interest",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tagMap := tt.args.tagMap
			getAllJSONTags(tt.args.typ, tagMap)
			for _, wantTag := range tt.wantTags {
				if _, ok := tagMap[wantTag]; !ok {
					t.Errorf("want tag(%v) is not in tag map\ntag map: %v", wantTag, tagMap)
				}
			}
		})
	}
}

func TestGetAllKeys(t *testing.T) {
	type args struct {
		jsonString string
	}
	tests := []struct {
		name    string
		args    args
		want    map[string]bool
		wantErr bool
	}{
		{
			name: "get all keys successfully",
			args: args{
				jsonString: ` {"id":1,"name":{"first_name":"first name","last_name":"last name"},
"emails":[{"email":"666666@gmail.com"}],"is_admin":false,"address":{"city":"Beijing","state":""},"interests":null}`,
			},
			want: map[string]bool{
				"id": true, "name": true, "first_name": true, "last_name": true, "emails": true, "email": true, "is_admin": true,
				"address": true, "city": true, "state": true, "interests": true,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAllKeys(tt.args.jsonString)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAllKeys() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetAllKeys() = %v, want %v", got, tt.want)
			}
		})
	}
}
