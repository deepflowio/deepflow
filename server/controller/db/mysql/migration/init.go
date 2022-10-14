/*
 * Copyright (c) 2022 Yunshan Networks
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

package migration

const (
	CREATE_TABLE_DB_VERSION = `CREATE TABLE IF NOT EXISTS db_version (
		version             CHAR(64),
		created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at          DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)ENGINE=innodb DEFAULT CHARSET=utf8;`
)

const (
	DROP_PROCEDURE  = `DROP PROCEDURE IF EXISTS init_auto_increment`
	CREATE_PROCDURE = `CREATE PROCEDURE init_auto_increment()
		BEGIN /* call this procedure in sql_restart_cmd after mysql restart */
			IF NOT EXISTS (SELECT 1 FROM information_schema.processlist
						WHERE user = 'system user') THEN /* is master */
				/*
				* Set AUTO_INCREMENT=4096 added by zhanghzhiming@yunshan.net.cn
				* Huawei CE6800 switches require VNI(vl2_id) to be no less than 4096
				*/
				SET @max_id = (SELECT IFNULL(MAX(id),0) FROM vl2);
				IF @max_id < 4096 THEN
					ALTER TABLE vl2 AUTO_INCREMENT=4096;
				END IF;
		
				/*
				* Avoid the TALBE_IDs 220/253/254/255 because policy routes strongswan/default/main/local
				* are using them, and ip route flush table 220/253/254/255 will cause the route
				* of control plane is removed.
				*/
				SET @max_id = (SELECT IFNULL(MAX(id),0) FROM vnet);
				IF @max_id < 256 THEN
					ALTER TABLE vnet AUTO_INCREMENT=256;
				END IF;
		
			END IF;
		END`
	CREATE_TRIGGER_RESOURCE_GROUP = `CREATE DEFINER='%s'@'localhost' TRIGGER resource_group_id AFTER INSERT
		ON resource_group FOR EACH ROW
		BEGIN
			IF (new.id > 64000) THEN
				signal sqlstate 'HY000' SET message_text = "resource_group id is above 64000, cannot insert.";
			END IF;
		END
		`
	CREATE_TRIGGER_NPB_TUNNEL = `
		CREATE DEFINER='%s'@'localhost' TRIGGER npb_tunnel_id AFTER INSERT
		ON npb_tunnel FOR EACH ROW
		BEGIN
			IF (new.id > 64000) THEN
				signal sqlstate 'HY000' SET message_text = "npb_tunnel id is above 64000, cannot insert.";
			END IF;
		END`
)
