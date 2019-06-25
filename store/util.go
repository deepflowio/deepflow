package store

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/influxdata/influxdb/client/v2"
	"github.com/influxdata/influxdb/models"
)

func queryResponse(c client.Client, db, rp, cmd string) (*client.Response, error) {
	q := client.Query{
		Command:         cmd,
		Database:        db,
		Precision:       "ns",
		RetentionPolicy: rp,
	}
	log.Debugf("client(%p) db=%s, %s", c, db, cmd)
	response, err := c.Query(q)
	if err != nil {
		log.Errorf("query on db(%s) cmd(%s) failed: %s", db, cmd, err.Error())
		return nil, err
	}

	if err := response.Error(); err != nil {
		log.Errorf("query on db(%s) cmd(%s) response failed: %s", db, cmd, err)
		return nil, err
	}

	return response, nil
}

func queryRows(c client.Client, db, rp, cmd string) ([]models.Row, error) {
	response, err := queryResponse(c, db, rp, cmd)
	if err != nil {
		return nil, err
	}

	if len(response.Results) == 0 {
		return nil, fmt.Errorf("cmd(%s) result is empty", cmd)
	}

	if len(response.Results[0].Series) == 0 {
		log.Debugf("cmd(%s) response series is empty", cmd)
	}

	return response.Results[0].Series, nil
}

func syncData(timestamp int64, database, measurement, rp string, primaryClient, replicaClient client.Client) (int, error) {
	syncCount := 0
	fieldNames, err := getFieldNames(primaryClient, database, rp, measurement)
	if err != nil {
		return 0, err
	}

	// 按列同步，减少内存占用
	for _, fieldName := range fieldNames {
		rows, err := getFieldData(primaryClient, database, rp, measurement, fieldName, timestamp)
		if err != nil {
			log.Errorf("primaryClient get(%s:%s:%s) field(%s) data failed: %s", database, rp, measurement, fieldName, err)
			return syncCount, err
		}

		err = writeFieldData(replicaClient, rows, database, rp, measurement, fieldName)
		if err != nil {
			log.Errorf("replicaClient write(%s:%s:%s) field(%s) data failed: %s", database, rp, measurement, fieldName, err)
			return syncCount, err
		}
		syncCount += len(rows.Values)
	}

	return syncCount, nil
}

func getFieldData(client client.Client, db, rp, measurement, field string, timestamp int64) (*models.Row, error) {
	cmd := fmt.Sprintf("select %s,*::tag from %s where time=%d ",
		field, measurement, timestamp)

	rows, err := queryRows(client, db, rp, cmd)
	if err != nil {
		return nil, err
	}

	if len(rows) > 0 {
		return &rows[0], nil
	} else {
		return nil, fmt.Errorf("getFieldData is empty")
	}
}

func writeFieldData(c client.Client, fieldData *models.Row, db, rp, measurement, fieldName string) error {
	bp, _ := client.NewBatchPoints(client.BatchPointsConfig{
		Database:        db,
		Precision:       "s",
		RetentionPolicy: rp,
	})

	for _, value := range fieldData.Values {
		tags := map[string]string{}
		fields := map[string]interface{}{}
		//get time
		timeValue := unmarshalInt64(value[0])

		//get tags field
		for i, columnName := range fieldData.Columns {
			if columnName == fieldName {
				fields[columnName] = unmarshalInt64(value[i])
				continue
			}
			switch v := value[i].(type) {
			case string:
				tags[columnName] = v
			}
		}

		if len(fields) != 1 {
			str := fmt.Sprintf("get filed column failed fieldName(%s), column names(%v)", fieldName, fieldData.Columns)
			log.Error(str)
			return fmt.Errorf(str)
		}

		//达到写入最大数量，需要先写入
		if len(bp.Points()) == MAX_BATCH_WRITE_POINTS {
			if err := c.Write(bp); err != nil {
				log.Errorf("db(%s) measurement(%s) write to local error: %s", db, measurement, err.Error())
				return err
			}
			bp, _ = client.NewBatchPoints(client.BatchPointsConfig{
				Database:        db,
				Precision:       "s",
				RetentionPolicy: rp,
			})
		}

		pt, err := client.NewPoint(measurement, tags, fields, time.Unix(0, timeValue))
		if err != nil {
			log.Errorf("New point error: %s", err.Error())
			return err
		}
		bp.AddPoint(pt)
	}
	// Write the batch
	err := c.Write(bp)
	if err != nil {
		log.Errorf("DB(%s) measurement(%s) write points(%d) error:%s", db, measurement, len(bp.Points()), err.Error())
		return err
	}
	log.Infof("writeFieldData DB(%s) measurement(%s) field(%s) write points(%d) success", db, measurement, fieldName, len(bp.Points()))
	return nil
}

func getFieldNames(client client.Client, db, rp, measurement string) ([]string, error) {
	fields := make([]string, 0)
	cmd := fmt.Sprintf("show field keys from %s",
		measurement)
	log.Debug("get fields cmd:", cmd)

	rows, err := queryRows(client, db, rp, cmd)
	if err != nil {
		return nil, err
	}

	if len(rows) > 0 {
		for _, value := range rows[0].Values {
			if len(value) == 2 {
				field, ok := value[0].(string)
				if ok {
					fields = append(fields, field)
				} else {
					log.Warning("parse field names value failed:", value)
				}
			} else {
				log.Warning("parse field names failed:", value)
			}
		}
	}

	if len(fields) == 0 {
		return nil, fmt.Errorf("get measurement(%s:%s) fields is empty", db, measurement)
	}

	return fields, nil
}

func unmarshalInt64(i interface{}) int64 {
	switch i.(type) {
	case json.Number:
		r, err := i.(json.Number).Int64()
		if err != nil {
			log.Errorf("json number convert failed %v %v", i, err.Error())
			return -1
		}
		return r
	case int:
		return int64(i.(int))
	case int64:
		return i.(int64)
	default:
		str := fmt.Sprintf("%v", i)
		ret, err := strconv.ParseInt(str, 10, 64)
		if err != nil {
			log.Errorf("unmarshalInt64 error: %v %s %s\n", i, str, err.Error())
			return -1
		}
		return ret
	}
}

func createRetentionPolicy(httpClient client.Client, dbName string, rp *RetentionPolicy) bool {
	setDefault := ""
	if rp.defaultFlag {
		setDefault = "default"
	}
	cmd := fmt.Sprintf("CREATE RETENTION POLICY %s ON %s DURATION %s REPLICATION 1 SHARD DURATION %s %s",
		rp.name, dbName, rp.duration, rp.shardDuration, setDefault)

	res, err := httpClient.Query(client.NewQuery(
		cmd, dbName, ""))
	if err := checkResponse(res, err); err != nil {
		log.Errorf("DB(%s) create retention policy(%s) failed, error info: %s", dbName, rp.name, err)
		return false
	}

	log.Infof("DB(%s) create retention policy(%s)", dbName, cmd)
	return true
}

func retentionPolicyExists(httpClient client.Client, db, rpName string) bool {
	// Validate if specified retention policy exists
	response, err := httpClient.Query(client.Query{Command: fmt.Sprintf("SHOW RETENTION POLICIES ON %q", db)})
	if err := checkResponse(response, err); err != nil {
		log.Warningf("DB(%s) check retention policy(%s) failed: %s", db, rpName, err)
		return false
	}

	for _, result := range response.Results {
		for _, row := range result.Series {
			for _, values := range row.Values {
				for k, v := range values {
					if k != 0 {
						continue
					}
					if v == rpName {
						return true
					}
				}
			}
		}
	}
	log.Warningf("DB(%s) retention policy(%s) not exist", db, rpName)

	return false
}

func getRetentionPolicy(httpClient client.Client, db, rpName string) *RetentionPolicy {
	// Validate if specified retention policy exists
	response, err := httpClient.Query(client.Query{Command: fmt.Sprintf("SHOW RETENTION POLICIES ON %q", db)})
	if err := checkResponse(response, err); err != nil {
		log.Warningf("DB(%s) check retention policy(%s) failed: %s", db, rpName, err)
		return nil
	}

	for _, result := range response.Results {
		for _, row := range result.Series {
			for _, values := range row.Values {
				for _, v := range values {
					if v == rpName {
						if len(values) > 4 {
							rp := &RetentionPolicy{name: rpName}
							var ok bool
							if rp.duration, ok = values[1].(string); !ok {
								return nil
							}
							if rp.shardDuration, ok = values[2].(string); !ok {
								return nil
							}
							if rp.defaultFlag, ok = values[4].(bool); !ok {
								return nil
							}
							return rp
						}
						return nil
					}
					break
				}
			}
		}
	}
	log.Warningf("can't get DB(%s) retention policy(%s)", db, rpName)

	return nil
}

func alterRetentionPolicy(httpClient client.Client, dbName string, rp *RetentionPolicy) bool {
	setDefault := ""
	if rp.defaultFlag {
		setDefault = "default"
	}
	cmd := fmt.Sprintf("ALTER RETENTION POLICY %s ON %s DURATION %s SHARD DURATION %s %s",
		rp.name, dbName, rp.duration, rp.shardDuration, setDefault)

	res, err := httpClient.Query(client.NewQuery(
		cmd, dbName, ""))
	if err := checkResponse(res, err); err != nil {
		log.Errorf("DB(%s) alter retention policy(%s) failed, error info: %s", dbName, rp.name, err)
		return false
	}

	log.Infof("DB(%s) alter retention policy(%s)", dbName, cmd)
	return true
}

func checkResponse(response *client.Response, err error) error {
	if err != nil {
		return err
	} else if err := response.Error(); err != nil {
		return err
	}
	return nil
}

func checkCreateRP(httpClient client.Client, db string, rp *RetentionPolicy) {
	if retentionPolicyExists(httpClient, db, rp.name) {
		alterRetentionPolicy(httpClient, db, rp)
	} else {
		createRetentionPolicy(httpClient, db, rp)
	}
}

func getCurrentDBs(httpClient client.Client) map[string]bool {
	dbs := make(map[string]bool)
	res, err := httpClient.Query(client.NewQuery("SHOW DATABASES", "", ""))
	if err := checkResponse(res, err); err != nil {
		log.Warning("Show databases failed, error info: %s", err)
	} else {
		databases := res.Results[0].Series[0].Values
		for _, col := range databases {
			if name, ok := col[0].(string); ok {
				dbs[name] = true
			}
		}
	}
	return dbs
}
