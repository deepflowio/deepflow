import os


FILE_NAME = 'pooled_meters.go'

BASE_CODE = """
package zerodoc

import (
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/pool"
)
"""

METER_CODE = """
var {pool_name} = pool.NewLockFreePool(func() interface{{}} {{
	return new({name})
}})

func Acquire{name}() *{name} {{
	return {pool_name}.Get().(*{name})
}}

func Release{name}(meter *{name}) {{
	if meter == nil {{
		return
	}}
	*meter = {name}{{}}
	{pool_name}.Put(meter)
}}

func Clone{name}(meter *{name}) *{name} {{
	newMeter := Acquire{name}()
	*newMeter = *meter
	return newMeter
}}

func (m *{name}) Clone() app.Meter {{
	return Clone{name}(m)
}}

func (m *{name}) Release() {{
	Release{name}(m)
}}
"""

def extract_name(file):
	with open(file, 'r') as f:
		for line in f:
			if line.startswith('type'):
				kws = line.split()
				if kws[2] == 'struct':
					return kws[1]
	return ''


def find_meters():
	names = []
	for f in os.listdir('.'):
		if f.endswith('_meter.go'):
			name = extract_name(f)
			if name is not None and name != '':
				names.append(name)
	return names


def main():
	with open(FILE_NAME, 'w') as f:
		f.write(BASE_CODE)
		for name in find_meters():
			f.write(METER_CODE.format(pool_name='pool' + name, name=name))


if __name__ == '__main__':
	main()
